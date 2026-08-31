package elmpay

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const MaxResponseBytes int64 = 1_048_576

type Client struct {
	BaseURL         *url.URL
	Token           string
	ProjectID       string
	HTTP            *http.Client
	MaximumAttempts int
}
type CheckoutSession struct {
	CheckoutSessionID string `json:"checkout_session_id"`
	ExpiresAt         string `json:"expires_at"`
	CheckoutURL       string `json:"checkout_url"`
}
type Problem struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Status  int    `json:"status"`
	Code    string `json:"code"`
	TraceID string `json:"trace_id"`
	Detail  string `json:"detail,omitempty"`
}
type Response struct {
	StatusCode int
	RequestID  string
	Data       CheckoutSession
}
type CheckoutRequest struct {
	BusinessOrderNo string `json:"business_order_no"`
	Amount          int64  `json:"amount"`
	Currency        string `json:"currency"`
	ReturnRouteID   string `json:"return_route_id,omitempty"`
}
type ConfirmRequest struct {
	PaymentMethodType      string `json:"payment_method_type"`
	PaymentMethodReference string `json:"payment_method_reference,omitempty"`
	Fingerprint            string `json:"fingerprint,omitempty"`
}

type ResponseTooLargeError struct{ RequestID string }
func (e *ResponseTooLargeError) Error() string { return "ElmPay response exceeds 1 MiB limit" }

type InvalidResponseError struct {
	Message   string
	RequestID string
	Cause     error
}
func (e *InvalidResponseError) Error() string { return "invalid ElmPay response: " + e.Message }
func (e *InvalidResponseError) Unwrap() error { return e.Cause }

type APIError struct {
	Problem   Problem
	RequestID string
}
func (e *APIError) Error() string {
	return fmt.Sprintf("ElmPay API error %d: %s", e.Problem.Status, e.Problem.Code)
}

func NewClient(baseURL, token, projectID string, timeout time.Duration, attempts int) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("base URL must be an origin-form HTTPS URL")
	}
	if token == "" || projectID == "" || timeout <= 0 || timeout > 5*time.Minute ||
		attempts < 1 || attempts > 5 {
		return nil, errors.New("token, project ID, bounded timeout and 1..5 attempts required")
	}
	return &Client{u, token, projectID, &http.Client{Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, attempts}, nil
}

func (c *Client) CreateCheckoutSession(ctx context.Context, payload CheckoutRequest, idempotencyKey string) (*Response, error) {
	if idempotencyKey == "" || payload.Amount <= 0 || payload.BusinessOrderNo == "" || payload.Currency == "" {
		return nil, errors.New("idempotency key, business order, currency and positive amount required")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return c.send(ctx, http.MethodPost, "/v1/checkout-sessions", body, idempotencyKey, http.StatusCreated)
}
func (c *Client) GetCheckoutSession(ctx context.Context, id string) (*Response, error) {
	return c.send(ctx, http.MethodGet, "/v1/checkout-sessions/"+url.PathEscape(id), nil, "", http.StatusOK)
}
func (c *Client) ConfirmCheckoutSession(ctx context.Context, id string, payload ConfirmRequest, idempotencyKey string) (*Response, error) {
	if idempotencyKey == "" || payload.PaymentMethodType == "" {
		return nil, errors.New("idempotency key and payment method type required")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return c.send(ctx, http.MethodPost, "/v1/checkout-sessions/"+url.PathEscape(id)+"/confirm", body, idempotencyKey, http.StatusOK)
}
func (c *Client) send(ctx context.Context, method, path string, body []byte, idem string, expectedStatus int) (*Response, error) {
	var last error
	retrySafe := method == http.MethodGet || idem != ""
	for attempt := 0; attempt < c.MaximumAttempts; attempt++ {
		reference, err := url.Parse(path)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, c.BaseURL.ResolveReference(reference).String(), bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("X-Project-Id", c.ProjectID)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if idem != "" {
			req.Header.Set("Idempotency-Key", idem)
		}
		res, transportErr := c.HTTP.Do(req)
		if transportErr == nil {
			out, responseErr := decodeResponse(res, expectedStatus)
			closeErr := res.Body.Close()
			if responseErr == nil && closeErr != nil {
				responseErr = &InvalidResponseError{Message: "failed to close response stream", RequestID: res.Header.Get("X-Request-Id"), Cause: closeErr}
			}
			if responseErr == nil {
				return out, nil
			}
			var apiErr *APIError
			if !errors.As(responseErr, &apiErr) || !retrySafe || attempt+1 == c.MaximumAttempts || !retryable(res.StatusCode) {
				return nil, responseErr
			}
		} else {
			last = transportErr
			if !retrySafe || attempt+1 == c.MaximumAttempts {
				return nil, transportErr
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(min(time.Second, 100*time.Millisecond*time.Duration(1<<attempt))):
		}
	}
	return nil, fmt.Errorf("request failed: %w", last)
}

func decodeResponse(res *http.Response, expectedStatus int) (*Response, error) {
	requestID := res.Header.Get("X-Request-Id")
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" && mediaType != "application/problem+json" {
		return nil, &InvalidResponseError{Message: "Content-Type must be JSON", RequestID: requestID, Cause: err}
	}
	raw, err := readBounded(res.Body, res.ContentLength, requestID)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(raw) {
		return nil, &InvalidResponseError{Message: "body is not valid UTF-8", RequestID: requestID}
	}
	if res.StatusCode == expectedStatus {
		if mediaType != "application/json" {
			return nil, &InvalidResponseError{Message: "success response must use application/json", RequestID: requestID}
		}
		var session CheckoutSession
		if err := decodeSingleJSON(raw, &session); err != nil {
			return nil, &InvalidResponseError{Message: "invalid checkout session JSON", RequestID: requestID, Cause: err}
		}
		if err := validateCheckoutSession(session); err != nil {
			return nil, &InvalidResponseError{Message: err.Error(), RequestID: requestID, Cause: err}
		}
		return &Response{StatusCode: res.StatusCode, RequestID: requestID, Data: session}, nil
	}
	if res.StatusCode >= 400 && res.StatusCode <= 599 {
		if mediaType != "application/problem+json" {
			return nil, &InvalidResponseError{Message: "error response must use application/problem+json", RequestID: requestID}
		}
		var problem Problem
		if err := decodeSingleJSON(raw, &problem); err != nil {
			return nil, &InvalidResponseError{Message: "invalid problem JSON", RequestID: requestID, Cause: err}
		}
		if err := validateProblem(problem, res.StatusCode); err != nil {
			return nil, &InvalidResponseError{Message: err.Error(), RequestID: requestID, Cause: err}
		}
		return nil, &APIError{Problem: problem, RequestID: requestID}
	}
	return nil, &InvalidResponseError{Message: fmt.Sprintf("unexpected HTTP status %d", res.StatusCode), RequestID: requestID}
}

func readBounded(body io.Reader, contentLength int64, requestID string) ([]byte, error) {
	if contentLength < -1 {
		return nil, &InvalidResponseError{Message: "invalid Content-Length", RequestID: requestID}
	}
	if contentLength > MaxResponseBytes {
		return nil, &ResponseTooLargeError{RequestID: requestID}
	}
	limited := &io.LimitedReader{R: body, N: MaxResponseBytes + 1}
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, &InvalidResponseError{Message: "failed to read response body", RequestID: requestID, Cause: err}
	}
	if int64(len(raw)) > MaxResponseBytes {
		return nil, &ResponseTooLargeError{RequestID: requestID}
	}
	return raw, nil
}

func decodeSingleJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateCheckoutSession(value CheckoutSession) error {
	if strings.TrimSpace(value.CheckoutSessionID) == "" {
		return errors.New("checkout_session_id must be a non-empty string")
	}
	if _, err := time.Parse(time.RFC3339, value.ExpiresAt); err != nil {
		return errors.New("expires_at must be an RFC 3339 date-time")
	}
	checkoutURL, err := url.Parse(value.CheckoutURL)
	if err != nil || checkoutURL.Scheme != "https" || checkoutURL.Host == "" {
		return errors.New("checkout_url must be an absolute HTTPS URL")
	}
	return nil
}

func validateProblem(value Problem, status int) error {
	problemType, err := url.Parse(value.Type)
	if err != nil || problemType.Scheme == "" {
		return errors.New("problem type must be an absolute URI")
	}
	if strings.TrimSpace(value.Title) == "" || strings.TrimSpace(value.Code) == "" || strings.TrimSpace(value.TraceID) == "" {
		return errors.New("problem title, code and trace_id must be non-empty strings")
	}
	if value.Status != status {
		return errors.New("problem status must match HTTP status")
	}
	return nil
}

func retryable(status int) bool { return status == 408 || status == 429 || status >= 500 }

func VerifyWebhook(secret, rawBody []byte, signatureHeader string, now time.Time, tolerance time.Duration) bool {
	if len(secret) < 32 || len(signatureHeader) > 4096 || tolerance < 0 {
		return false
	}
	parts := map[string]string{}
	for _, part := range strings.Split(signatureHeader, ",") {
		pair := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(pair) != 2 {
			return false
		}
		key, value := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
		if (key != "t" && key != "v1") || value == "" || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
			return false
		}
		if _, exists := parts[key]; exists {
			return false
		}
		parts[key] = value
	}
	if len(parts) != 2 || !allASCIIDigits(parts["t"]) || len(parts["t"]) > 19 ||
		!validRawURLSignature(parts["v1"]) {
		return false
	}
	timestamp, err := strconv.ParseInt(parts["t"], 10, 64)
	if err != nil || timestamp < 0 || now.Sub(time.Unix(timestamp, 0)).Abs() > tolerance {
		return false
	}
	supplied, err := base64.RawURLEncoding.DecodeString(parts["v1"])
	if err != nil || len(supplied) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strconv.FormatInt(timestamp, 10) + "."))
	mac.Write(rawBody)
	return hmac.Equal(mac.Sum(nil), supplied)
}

func allASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func validRawURLSignature(value string) bool {
	if len(value) != 43 { // 32-byte HMAC without base64url padding
		return false
	}
	for _, char := range value {
		if !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}
