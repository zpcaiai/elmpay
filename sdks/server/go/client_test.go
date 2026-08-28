package elmpay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{}`))
	}))
	defer server.Close()
	project := "10000000-0000-4000-8000-000000000002"
	client, err := NewClient(server.URL, "token", project, time.Second, 1)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTP = server.Client()
	if _, err := client.CreateCheckoutSession(context.Background(), CheckoutRequest{"order-1", 1250, "USD", "complete"}, "create-idempotency-0001"); err != nil {
		t.Fatal(err)
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
}
