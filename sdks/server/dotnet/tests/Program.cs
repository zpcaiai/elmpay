using System.Net;
using System.Text.Json;
using ElmPay;

var handler = new RecordingHandler();
var project = "10000000-0000-4000-8000-000000000002";
var client = new ElmPayClient(new Uri("https://api.example/"), "token", project,
    TimeSpan.FromSeconds(1), 1, handler);
await client.CreateCheckoutSessionAsync(new CheckoutRequest("order-1", 1250, "USD", "complete"),
    "create-idempotency-0001");
await client.GetCheckoutSessionAsync("session/unsafe");
await client.ConfirmCheckoutSessionAsync("session-1",
    new ConfirmRequest("stripe_card", "psp://tok/1", "fp"), "confirm-idempotency-001");

Expect(handler.Requests.Select(value => value.Path).SequenceEqual(new[] {
    "/v1/checkout-sessions", "/v1/checkout-sessions/session%2Funsafe",
    "/v1/checkout-sessions/session-1/confirm" }), "canonical paths");
Expect(handler.Requests.All(value => value.ProjectId == project), "X-Project-Id");
using var create = JsonDocument.Parse(handler.Requests[0].Body!);
var root = create.RootElement;
Expect(root.GetProperty("business_order_no").GetString() == "order-1", "business_order_no");
Expect(root.GetProperty("amount").ValueKind == JsonValueKind.Number
    && root.GetProperty("amount").GetInt64() == 1250, "integer amount");
foreach (var drift in new[] { "project_id", "order_reference", "amount_minor", "return_uri" })
    Expect(!root.TryGetProperty(drift, out _), $"legacy field {drift}");
using var confirm = JsonDocument.Parse(handler.Requests[2].Body!);
Expect(confirm.RootElement.GetProperty("payment_method_type").GetString() == "stripe_card",
    "confirm body");
using var signingVector = JsonDocument.Parse(
    File.ReadAllText("contracts/webhooks/signing-v1.json"));
var signing = signingVector.RootElement;
var encodedSecret = signing.GetProperty("secret_base64url").GetString()!;
var secret = Convert.FromBase64String(encodedSecret.Replace('-', '+').Replace('_', '/')
    .PadRight((encodedSecret.Length + 3) / 4 * 4, '='));
var rawBody = System.Text.Encoding.UTF8.GetBytes(
    signing.GetProperty("raw_body_utf8").GetString()!);
var timestamp = signing.GetProperty("timestamp").GetInt64();
Expect(ElmPayClient.VerifyWebhook(secret, rawBody,
    signing.GetProperty("signature_header").GetString()!,
    DateTimeOffset.FromUnixTimeSeconds(timestamp), TimeSpan.FromMinutes(5)),
    "webhook golden vector");
Expect(!ElmPayClient.VerifyWebhook(secret, "{}"u8,
    signing.GetProperty("signature_header").GetString()!,
    DateTimeOffset.FromUnixTimeSeconds(timestamp), TimeSpan.FromMinutes(5)),
    "webhook tampered bytes");
Console.WriteLine("dotnet checkout contract: PASS (3 requests)");

static void Expect(bool condition, string name) {
    if (!condition) throw new InvalidOperationException($"contract assertion failed: {name}");
}

sealed record Observed(string Method, string Path, string ProjectId, string? Body);
sealed class RecordingHandler : HttpMessageHandler {
    public List<Observed> Requests { get; } = [];
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken) {
        var body = request.Content is null ? null
            : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Add(new Observed(request.Method.Method, request.RequestUri!.AbsolutePath,
            request.Headers.GetValues("X-Project-Id").Single(), body));
        return new HttpResponseMessage(HttpStatusCode.OK) {
            Content = new StringContent("{}")
        };
    }
}
