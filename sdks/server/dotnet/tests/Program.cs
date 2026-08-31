using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using ElmPay;

var handler = new RecordingHandler();
var project = "10000000-0000-4000-8000-000000000002";
foreach (var timeout in new[] { TimeSpan.Zero, TimeSpan.FromTicks(TimeSpan.FromMinutes(5).Ticks + 1) })
{
    try
    {
        _ = new ElmPayClient(new Uri("https://api.example/"), "token", project, timeout, 1,
            new RecordingHandler());
        throw new InvalidOperationException("unbounded timeout was accepted");
    }
    catch (ArgumentException)
    {
        // expected fail-closed constructor rejection
    }
}
try
{
    _ = new ElmPayClient(new Uri("https://user:pass@api.example/"), "token", project,
        TimeSpan.FromSeconds(1), 1, new RecordingHandler());
    throw new InvalidOperationException("unsafe base URI was accepted");
}
catch (ArgumentException)
{
    // expected fail-closed constructor rejection
}
var client = new ElmPayClient(new Uri("https://api.example/"), "token", project,
    TimeSpan.FromSeconds(1), 1, handler);
var createdResponse = await client.CreateCheckoutSessionAsync(
    new CheckoutRequest("order-1", 1250, "USD", "complete"), "create-idempotency-0001");
await client.GetCheckoutSessionAsync("session/unsafe");
await client.ConfirmCheckoutSessionAsync("session-1",
    new ConfirmRequest("stripe_card", "psp://tok/1", "fp"), "confirm-idempotency-001");

Expect(handler.Requests.Select(value => value.Path).SequenceEqual(new[] {
    "/v1/checkout-sessions", "/v1/checkout-sessions/session%2Funsafe",
    "/v1/checkout-sessions/session-1/confirm" }), "canonical paths");
Expect(handler.Requests.All(value => value.ProjectId == project), "X-Project-Id");
Expect(createdResponse.StatusCode == HttpStatusCode.Created
    && createdResponse.Data.CheckoutSessionId == "cs_123", "typed create response");
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
var rawBody = Encoding.UTF8.GetBytes(signing.GetProperty("raw_body_utf8").GetString()!);
var timestamp = signing.GetProperty("timestamp").GetInt64();
Expect(ElmPayClient.VerifyWebhook(secret, rawBody,
    signing.GetProperty("signature_header").GetString()!,
    DateTimeOffset.FromUnixTimeSeconds(timestamp), TimeSpan.FromMinutes(5)),
    "webhook golden vector");
Expect(!ElmPayClient.VerifyWebhook(secret, "{}"u8,
    signing.GetProperty("signature_header").GetString()!,
    DateTimeOffset.FromUnixTimeSeconds(timestamp), TimeSpan.FromMinutes(5)),
    "webhook tampered bytes");
var signatureHeader = signing.GetProperty("signature_header").GetString()!;
Expect(!ElmPayClient.VerifyWebhook(secret, rawBody, signatureHeader + ",t=" + timestamp,
    DateTimeOffset.FromUnixTimeSeconds(timestamp), TimeSpan.FromMinutes(5)),
    "webhook duplicate timestamp");
Expect(!ElmPayClient.VerifyWebhook(secret, rawBody, signatureHeader + ",v1=bad",
    DateTimeOffset.FromUnixTimeSeconds(timestamp), TimeSpan.FromMinutes(5)),
    "webhook duplicate signature");
Expect(!ElmPayClient.VerifyWebhook(secret, rawBody, signatureHeader.Replace("t=", "t=+"),
    DateTimeOffset.FromUnixTimeSeconds(timestamp), TimeSpan.FromMinutes(5)),
    "webhook non-canonical timestamp");

var oversizedContent = new StreamContent(
    new NonSeekableMemoryStream(new byte[ElmPayClient.MaxResponseBytes + 1]));
oversizedContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
await ExpectThrowsAsync<ResponseTooLargeException>(() => new ElmPayClient(
    new Uri("https://api.example/"), "token", project, TimeSpan.FromSeconds(1), 1,
    new StaticHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) {
        Content = oversizedContent
    })).GetCheckoutSessionAsync("cs_123"), "oversized chunked response");

await ExpectThrowsAsync<InvalidResponseException>(() => ClientReturning(
    HttpStatusCode.OK, TestResponses.SessionJson, "text/html").GetCheckoutSessionAsync("cs_123"),
    "wrong response content type");
await ExpectThrowsAsync<InvalidResponseException>(() => ClientReturning(
    HttpStatusCode.OK, "{\"checkout_session_id\":\"cs_123\"}", "application/json")
    .GetCheckoutSessionAsync("cs_123"), "invalid typed schema");
await ExpectThrowsAsync<InvalidResponseException>(() => ClientReturning(
    HttpStatusCode.OK, TestResponses.SessionJson, "application/json")
    .CreateCheckoutSessionAsync(new CheckoutRequest("order-1", 100, "USD"), "idem-1"),
    "unexpected create status");

try {
    await ClientReturning(HttpStatusCode.PaymentRequired,
        "{\"type\":\"https://docs.example/problems/declined\",\"title\":\"Declined\",\"status\":402,\"code\":\"payment_declined\",\"trace_id\":\"trace-1\"}",
        "application/problem+json").GetCheckoutSessionAsync("cs_123");
    throw new InvalidOperationException("contract assertion failed: mapped problem not raised");
} catch (ElmPayApiException error) {
    Expect(error.StatusCode == HttpStatusCode.PaymentRequired
        && error.Problem.Code == "payment_declined" && error.RequestId == "request-1",
        "mapped problem and bound status");
}

Console.WriteLine("dotnet checkout contract: PASS (response hardening included)");

ElmPayClient ClientReturning(HttpStatusCode status, string responseBody, string contentType) =>
    new(new Uri("https://api.example/"), "token", project, TimeSpan.FromSeconds(1), 1,
        new StaticHandler(_ => {
            var response = new HttpResponseMessage(status) {
                Content = new StringContent(responseBody, Encoding.UTF8, contentType)
            };
            response.Headers.Add("X-Request-Id", "request-1");
            return response;
        }));

static void Expect(bool condition, string name) {
    if (!condition) throw new InvalidOperationException($"contract assertion failed: {name}");
}

static async Task ExpectThrowsAsync<T>(Func<Task> action, string name) where T : Exception {
    try { await action(); }
    catch (T) { return; }
    throw new InvalidOperationException($"contract assertion failed: {name}");
}

static class TestResponses {
    public const string SessionJson =
        "{\"checkout_session_id\":\"cs_123\",\"expires_at\":\"2026-08-30T12:00:00Z\",\"checkout_url\":\"https://checkout.example/cs_123\"}";
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
        var status = request.Method == HttpMethod.Post
            && request.RequestUri.AbsolutePath == "/v1/checkout-sessions"
            ? HttpStatusCode.Created : HttpStatusCode.OK;
        return new HttpResponseMessage(status) {
            Content = new StringContent(TestResponses.SessionJson, Encoding.UTF8, "application/json")
        };
    }
}

sealed class StaticHandler : HttpMessageHandler {
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _response;
    public StaticHandler(Func<HttpRequestMessage, HttpResponseMessage> response) =>
        _response = response;
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken) => Task.FromResult(_response(request));
}

sealed class NonSeekableMemoryStream : MemoryStream {
    public NonSeekableMemoryStream(byte[] bytes) : base(bytes) { }
    public override bool CanSeek => false;
}
