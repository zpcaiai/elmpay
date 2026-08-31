package elmpay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCheckoutContract(t *testing.T) {
	type observed struct {
		method, path, project, idempotency string
		body                               map[string]any
	}
	requests := make(chan observed, 3)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		decoded := map[string]any{}
		if len(body) > 0 {
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatal(err)
			}
		}
		requests <- observed{request.Method, request.URL.EscapedPath(), request.Header.Get("X-Project-Id"), request.Header.Get("Idempotency-Key"), decoded}
		writer.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost && request.URL.Path == "/v1/checkout-sessions" {
			writer.WriteHeader(http.StatusCreated)
		} else {
			writer.WriteHeader(http.StatusOK)
		}
		_, _ = writer.Write([]byte(`{"checkout_session_id":"cs_123","expires_at":"2026-08-30T12:00:00Z","checkout_url":"https://checkout.example/cs_123"}`))
	}))
	defer server.Close()
	project := "10000000-0000-4000-8000-000000000002"
	client, err := NewClient(server.URL, "token", project, time.Second, 1)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTP = server.Client()
	created, err := client.CreateCheckoutSession(context.Background(), CheckoutRequest{"order-1", 1250, "USD", "complete"}, "create-idempotency-0001")
	if err != nil {
		t.Fatal(err)
	}
	if created.StatusCode != http.StatusCreated || created.Data.CheckoutSessionID != "cs_123" {
		t.Fatalf("typed create response not decoded: %#v", created)
	}
	if _, err := client.GetCheckoutSession(context.Background(), "session/unsafe"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ConfirmCheckoutSession(context.Background(), "session-1", ConfirmRequest{"stripe_card", "psp://tok/1", "fp"}, "confirm-idempotency-001"); err != nil {
		t.Fatal(err)
	}
	create, get, confirm := <-requests, <-requests, <-requests
	if create.method != http.MethodPost || create.path != "/v1/checkout-sessions" || create.project != project {
		t.Fatalf("bad create request: %#v", create)
	}
	if amount, ok := create.body["amount"].(float64); !ok || amount != 1250 {
		t.Fatalf("amount not serialized as JSON integer: %#v", create.body)
	}
	for _, drift := range []string{"project_id", "order_reference", "amount_minor", "return_uri"} {
		if _, exists := create.body[drift]; exists {
			t.Fatalf("legacy field %s serialized", drift)
		}
	}
	if get.method != http.MethodGet || get.path != "/v1/checkout-sessions/session%2Funsafe" || get.project != project {
		t.Fatalf("bad get request: %#v", get)
	}
	if confirm.path != "/v1/checkout-sessions/session-1/confirm" || confirm.body["payment_method_type"] != "stripe_card" || confirm.idempotency != "confirm-idempotency-001" {
		t.Fatalf("bad confirm request: %#v", confirm)
	}
}

func TestNewClientRejectsUnboundedTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second, 5*time.Minute + time.Nanosecond} {
		if _, err := NewClient("https://api.example/", "token", "project", timeout, 1); err == nil {
			t.Fatalf("timeout %s was accepted", timeout)
		}
	}
	for _, baseURL := range []string{"https://user:pass@api.example/", "https://api.example/?x=1", "https://api.example/#fragment"} {
		if _, err := NewClient(baseURL, "token", "project", time.Second, 1); err == nil {
			t.Fatalf("unsafe base URL %q was accepted", baseURL)
		}
	}
}

func TestRejectsOversizedChunkedResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Request-Id", "request-1")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(bytes.Repeat([]byte{'x'}, int(MaxResponseBytes+1)))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "token", "project", time.Second, 1)
	if err != nil { t.Fatal(err) }
	client.HTTP = server.Client()
	_, err = client.GetCheckoutSession(context.Background(), "cs_123")
	var tooLarge *ResponseTooLargeError
	if !errors.As(err, &tooLarge) || tooLarge.RequestID != "request-1" {
		t.Fatalf("expected bounded response error, got %v", err)
	}
}

func TestRejectsContentTypeStatusAndSchemaDrift(t *testing.T) {
	tests := []struct {
		name, contentType, body string
		status                  int
	}{
		{"content type", "text/html", `{}`, http.StatusOK},
		{"schema", "application/json", `{"checkout_session_id":"cs_123"}`, http.StatusOK},
		{"status", "application/json", `{"checkout_session_id":"cs_123","expires_at":"2026-08-30T12:00:00Z","checkout_url":"https://checkout.example/cs_123"}`, http.StatusCreated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", test.contentType)
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			client, err := NewClient(server.URL, "token", "project", time.Second, 1)
			if err != nil { t.Fatal(err) }
			client.HTTP = server.Client()
			_, err = client.GetCheckoutSession(context.Background(), "cs_123")
			var invalid *InvalidResponseError
			if !errors.As(err, &invalid) { t.Fatalf("expected invalid response error, got %v", err) }
		})
	}
}

func TestMapsProblemAndBindsHTTPStatus(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/problem+json")
		writer.Header().Set("X-Request-Id", "request-1")
		writer.WriteHeader(http.StatusPaymentRequired)
		_, _ = writer.Write([]byte(`{"type":"https://docs.example/problems/declined","title":"Declined","status":402,"code":"payment_declined","trace_id":"trace-1"}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "token", "project", time.Second, 1)
	if err != nil { t.Fatal(err) }
	client.HTTP = server.Client()
	_, err = client.GetCheckoutSession(context.Background(), "cs_123")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Problem.Code != "payment_declined" || apiErr.RequestID != "request-1" {
		t.Fatalf("expected mapped API error, got %v", err)
	}
}

func TestVerifyWebhook(t *testing.T) {
	data, err := os.ReadFile("../../../contracts/webhooks/signing-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Timestamp int64  `json:"timestamp"`
		Secret    string `json:"secret_base64url"`
		Body      string `json:"raw_body_utf8"`
		Header    string `json:"signature_header"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	secret, err := base64.RawURLEncoding.DecodeString(vector.Secret)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(vector.Body)
	if !VerifyWebhook(secret, body, vector.Header, time.Unix(vector.Timestamp, 0), time.Minute) {
		t.Fatal("valid signature rejected")
	}
	if VerifyWebhook(secret, []byte(`{}`), vector.Header, time.Unix(vector.Timestamp, 0), time.Minute) {
		t.Fatal("tampered body accepted")
	}
	if VerifyWebhook(secret, body, vector.Header+",t="+strconv.FormatInt(vector.Timestamp, 10),
		time.Unix(vector.Timestamp, 0), time.Minute) {
		t.Fatal("duplicate timestamp accepted")
	}
	if VerifyWebhook(secret, body, vector.Header+",v1=bad", time.Unix(vector.Timestamp, 0), time.Minute) {
		t.Fatal("duplicate signature accepted")
	}
	if VerifyWebhook(secret, body, strings.Replace(vector.Header, "t=", "t=+", 1),
		time.Unix(vector.Timestamp, 0), time.Minute) {
		t.Fatal("non-canonical timestamp accepted")
	}
}
