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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	BaseURL         *url.URL
	Token           string
	ProjectID       string
	HTTP            *http.Client
	MaximumAttempts int
}
type Response struct {
	StatusCode int
	RequestID  string
	Body       []byte
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

func NewClient(baseURL, token, projectID string, timeout time.Duration, attempts int) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" {
		return nil, errors.New("base URL must use HTTPS")
	}
	if token == "" || projectID == "" || attempts < 1 || attempts > 5 {
		return nil, errors.New("token, project ID and 1..5 attempts required")
	}
	return &Client{u, token, projectID, &http.Client{Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, attempts}, nil
}

func (c *Client) CreateCheckoutSession(ctx context.Context, payload CheckoutRequest, idempotencyKey string) (*Response, error) {
	if idempotencyKey == "" || payload.Amount <= 0 || payload.BusinessOrderNo == "" || payload.Currency == "" {
		return nil, errors.New("idempotency key and positive amount required")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return c.send(ctx, http.MethodPost, "/v1/checkout-sessions", body, idempotencyKey)
}
func (c *Client) GetCheckoutSession(ctx context.Context, id string) (*Response, error) {
	return c.send(ctx, http.MethodGet, "/v1/checkout-sessions/"+url.PathEscape(id), nil, "")
}
func (c *Client) ConfirmCheckoutSession(ctx context.Context, id string, payload ConfirmRequest, idempotencyKey string) (*Response, error) {
	if idempotencyKey == "" || payload.PaymentMethodType == "" {
		return nil, errors.New("idempotency key and payment method type required")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return c.send(ctx, http.MethodPost, "/v1/checkout-sessions/"+url.PathEscape(id)+"/confirm", body, idempotencyKey)
}
func (c *Client) send(ctx context.Context, method, path string, body []byte, idem string) (*Response, error) {
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
		res, err := c.HTTP.Do(req)
		if err == nil {
			content, readErr := io.ReadAll(io.LimitReader(res.Body, 4<<20))
			res.Body.Close()
			if readErr != nil {
				return nil, readErr
			}
			out := &Response{res.StatusCode, res.Header.Get("X-Request-Id"), content}
			if !retrySafe || attempt+1 == c.MaximumAttempts || !retryable(res.StatusCode) {
				return out, nil
			}
		} else {
			last = err
			if !retrySafe || attempt+1 == c.MaximumAttempts {
				return nil, err
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
func retryable(status int) bool { return status == 408 || status == 429 || status >= 500 }

func VerifyWebhook(secret, rawBody []byte, signatureHeader string, now time.Time, tolerance time.Duration) bool {
	if len(secret) < 32 {
		return false
	}
	parts := map[string]string{}
	for _, part := range strings.Split(signatureHeader, ",") {
		pair := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(pair) == 2 {
			parts[pair[0]] = pair[1]
		}
	}
	timestamp, err := strconv.ParseInt(parts["t"], 10, 64)
	if err != nil || now.Sub(time.Unix(timestamp, 0)).Abs() > tolerance {
		return false
	}
	supplied, err := base64.RawURLEncoding.DecodeString(parts["v1"])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strconv.FormatInt(timestamp, 10) + "."))
	mac.Write(rawBody)
	return hmac.Equal(mac.Sum(nil), supplied)
}
