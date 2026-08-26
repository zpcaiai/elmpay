using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ElmPay;

public sealed record ApiResponse(HttpStatusCode StatusCode, string Body, string RequestId);
public sealed record CheckoutRequest(
    [property: JsonPropertyName("business_order_no")] string BusinessOrderNo,
    [property: JsonPropertyName("amount")] long Amount,
    [property: JsonPropertyName("currency")] string Currency,
    [property: JsonPropertyName("return_route_id")] string? ReturnRouteId = null);
public sealed record ConfirmRequest(
    [property: JsonPropertyName("payment_method_type")] string PaymentMethodType,
    [property: JsonPropertyName("payment_method_reference")] string? PaymentMethodReference = null,
    [property: JsonPropertyName("fingerprint")] string? Fingerprint = null);

public sealed class ElmPayClient
{
    private readonly Uri _baseUri; private readonly string _token; private readonly string _projectId; private readonly HttpClient _http; private readonly int _attempts;
    public ElmPayClient(Uri baseUri, string token, string projectId, TimeSpan timeout, int maximumAttempts = 3, HttpMessageHandler? handler = null)
    {
        if (baseUri.Scheme != Uri.UriSchemeHttps) throw new ArgumentException("baseUri must use HTTPS");
        if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(projectId) || maximumAttempts is < 1 or > 5) throw new ArgumentException("token, project ID and 1..5 attempts required");
        _baseUri = baseUri; _token = token; _projectId = projectId; _attempts = maximumAttempts; _http = handler is null ? new HttpClient() : new HttpClient(handler); _http.Timeout = timeout;
    }
    public Task<ApiResponse> CreateCheckoutSessionAsync(CheckoutRequest payload, string idempotencyKey, CancellationToken cancellation = default) {
        if (payload.Amount <= 0 || string.IsNullOrWhiteSpace(payload.BusinessOrderNo) || string.IsNullOrWhiteSpace(payload.Currency)) throw new ArgumentException("business order, currency and positive amount required");
        return SendAsync(HttpMethod.Post, "/v1/checkout-sessions", JsonSerializer.Serialize(payload,
            new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull }), idempotencyKey, cancellation);
    }
    public Task<ApiResponse> GetCheckoutSessionAsync(string id, CancellationToken cancellation = default) =>
        SendAsync(HttpMethod.Get, "/v1/checkout-sessions/" + Uri.EscapeDataString(id), null, null, cancellation);
    public Task<ApiResponse> ConfirmCheckoutSessionAsync(string id, ConfirmRequest payload, string idempotencyKey, CancellationToken cancellation = default) {
        if (string.IsNullOrWhiteSpace(payload.PaymentMethodType)) throw new ArgumentException("payment method type required");
        return SendAsync(HttpMethod.Post, "/v1/checkout-sessions/" + Uri.EscapeDataString(id) + "/confirm",
            JsonSerializer.Serialize(payload, new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull }), idempotencyKey, cancellation);
    }

    private async Task<ApiResponse> SendAsync(HttpMethod method, string path, string? body, string? idempotencyKey, CancellationToken cancellation)
    {
        if (method == HttpMethod.Post && string.IsNullOrWhiteSpace(idempotencyKey)) throw new ArgumentException("idempotency key required");
        var retrySafe = method == HttpMethod.Get || idempotencyKey is not null;
        for (var attempt = 0; attempt < _attempts; attempt++)
        {
            using var request = new HttpRequestMessage(method, new Uri(_baseUri, path));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token); request.Headers.Accept.ParseAdd("application/json");
            request.Headers.Add("X-Project-Id", _projectId);
            if (idempotencyKey is not null) request.Headers.Add("Idempotency-Key", idempotencyKey);
            if (body is not null) request.Content = new StringContent(body, Encoding.UTF8, "application/json");
            try {
                using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation).ConfigureAwait(false);
                var result = new ApiResponse(response.StatusCode, await response.Content.ReadAsStringAsync(cancellation).ConfigureAwait(false),
                    response.Headers.TryGetValues("X-Request-Id", out var ids) ? ids.FirstOrDefault() ?? "" : "");
                if (!retrySafe || attempt + 1 == _attempts || !Retryable(response.StatusCode)) return result;
            } catch (HttpRequestException) when (retrySafe && attempt + 1 < _attempts) { }
              catch (TaskCanceledException) when (!cancellation.IsCancellationRequested && retrySafe && attempt + 1 < _attempts) { }
            await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(1000, 100 * (1 << attempt))), cancellation).ConfigureAwait(false);
        }
        throw new HttpRequestException("bounded retry exhausted");
    }
    private static bool Retryable(HttpStatusCode code) => code is HttpStatusCode.RequestTimeout or (HttpStatusCode)429 || (int)code >= 500;

    public static bool VerifyWebhook(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> rawBody, string header, DateTimeOffset now, TimeSpan tolerance)
    {
        if (secret.Length < 32) return false; var parts = header.Split(',').Select(p => p.Trim().Split('=', 2)).Where(p => p.Length == 2).ToDictionary(p => p[0], p => p[1]);
        if (!parts.TryGetValue("t", out var rawTimestamp) || !long.TryParse(rawTimestamp, out var timestamp) ||
            (now - DateTimeOffset.FromUnixTimeSeconds(timestamp)).Duration() > tolerance || !parts.TryGetValue("v1", out var signature)) return false;
        byte[] supplied; try { supplied = Convert.FromBase64String(signature.Replace('-', '+').Replace('_', '/').PadRight((signature.Length + 3) / 4 * 4, '=')); } catch (FormatException) { return false; }
        using var hmac = new HMACSHA256(secret.ToArray()); var prefix = Encoding.ASCII.GetBytes(timestamp + ".");
        var message = new byte[prefix.Length + rawBody.Length]; prefix.CopyTo(message, 0); rawBody.CopyTo(message.AsSpan(prefix.Length));
        return CryptographicOperations.FixedTimeEquals(hmac.ComputeHash(message), supplied);
    }
}
