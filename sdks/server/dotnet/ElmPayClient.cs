using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace ElmPay;

public sealed record CheckoutSession(string CheckoutSessionId, string ExpiresAt, string CheckoutUrl);
public sealed record ApiProblem(string Type, string Title, int Status, string Code, string TraceId, string? Detail);
public sealed record ApiResponse(HttpStatusCode StatusCode, CheckoutSession Data, string RequestId);
public sealed record CheckoutRequest(
    [property: JsonPropertyName("business_order_no")] string BusinessOrderNo,
    [property: JsonPropertyName("amount")] long Amount,
    [property: JsonPropertyName("currency")] string Currency,
    [property: JsonPropertyName("return_route_id")] string? ReturnRouteId = null);
public sealed record ConfirmRequest(
    [property: JsonPropertyName("payment_method_type")] string PaymentMethodType,
    [property: JsonPropertyName("payment_method_reference")] string? PaymentMethodReference = null,
    [property: JsonPropertyName("fingerprint")] string? Fingerprint = null);

public class ElmPayResponseException : Exception
{
    public string RequestId { get; }
    public ElmPayResponseException(string message, string requestId = "", Exception? inner = null)
        : base(message, inner) => RequestId = requestId;
}
public sealed class ResponseTooLargeException : ElmPayResponseException
{
    public ResponseTooLargeException(string requestId) : base("ElmPay response exceeds 1 MiB limit", requestId) { }
}
public class InvalidResponseException : ElmPayResponseException
{
    public InvalidResponseException(string message, string requestId = "", Exception? inner = null)
        : base("Invalid ElmPay response: " + message, requestId, inner) { }
}
public sealed class ElmPayApiException : ElmPayResponseException
{
    public ApiProblem Problem { get; }
    public HttpStatusCode StatusCode => (HttpStatusCode)Problem.Status;
    public ElmPayApiException(ApiProblem problem, string requestId)
        : base($"ElmPay API error {problem.Status}: {problem.Code}", requestId) => Problem = problem;
}

public sealed class ElmPayClient
{
    public const int MaxResponseBytes = 1_048_576;
    private static readonly Regex Rfc3339 = new(
        @"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private readonly Uri _baseUri;
    private readonly string _token;
    private readonly string _projectId;
    private readonly HttpClient _http;
    private readonly int _attempts;

    public ElmPayClient(Uri baseUri, string token, string projectId, TimeSpan timeout,
        int maximumAttempts = 3, HttpMessageHandler? handler = null)
    {
        if (baseUri is null || baseUri.Scheme != Uri.UriSchemeHttps || !baseUri.IsAbsoluteUri
            || !string.IsNullOrEmpty(baseUri.UserInfo) || !string.IsNullOrEmpty(baseUri.Query)
            || !string.IsNullOrEmpty(baseUri.Fragment))
            throw new ArgumentException("baseUri must be an origin-form HTTPS URL");
        if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(projectId)
            || timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(5)
            || maximumAttempts is < 1 or > 5)
            throw new ArgumentException("token, project ID, bounded timeout and 1..5 attempts required");
        _baseUri = baseUri;
        _token = token;
        _projectId = projectId;
        _attempts = maximumAttempts;
        _http = handler is null
            ? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            : new HttpClient(handler);
        _http.Timeout = timeout;
    }

    public Task<ApiResponse> CreateCheckoutSessionAsync(CheckoutRequest payload,
        string idempotencyKey, CancellationToken cancellation = default)
    {
        if (payload.Amount <= 0 || string.IsNullOrWhiteSpace(payload.BusinessOrderNo)
            || string.IsNullOrWhiteSpace(payload.Currency))
            throw new ArgumentException("business order, currency and positive amount required");
        return SendAsync(HttpMethod.Post, "/v1/checkout-sessions",
            JsonSerializer.Serialize(payload,
                new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull }),
            idempotencyKey, HttpStatusCode.Created, cancellation);
    }

    public Task<ApiResponse> GetCheckoutSessionAsync(string id, CancellationToken cancellation = default) =>
        SendAsync(HttpMethod.Get, "/v1/checkout-sessions/" + Uri.EscapeDataString(id), null, null,
            HttpStatusCode.OK, cancellation);

    public Task<ApiResponse> ConfirmCheckoutSessionAsync(string id, ConfirmRequest payload,
        string idempotencyKey, CancellationToken cancellation = default)
    {
        if (string.IsNullOrWhiteSpace(payload.PaymentMethodType))
            throw new ArgumentException("payment method type required");
        return SendAsync(HttpMethod.Post,
            "/v1/checkout-sessions/" + Uri.EscapeDataString(id) + "/confirm",
            JsonSerializer.Serialize(payload,
                new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull }),
            idempotencyKey, HttpStatusCode.OK, cancellation);
    }

    private async Task<ApiResponse> SendAsync(HttpMethod method, string path, string? body,
        string? idempotencyKey, HttpStatusCode expectedStatus, CancellationToken cancellation)
    {
        if (method == HttpMethod.Post && string.IsNullOrWhiteSpace(idempotencyKey))
            throw new ArgumentException("idempotency key required");
        var retrySafe = method == HttpMethod.Get || idempotencyKey is not null;
        for (var attempt = 0; attempt < _attempts; attempt++)
        {
            using var request = new HttpRequestMessage(method, new Uri(_baseUri, path));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
            request.Headers.Accept.ParseAdd("application/json");
            request.Headers.Add("X-Project-Id", _projectId);
            if (idempotencyKey is not null) request.Headers.Add("Idempotency-Key", idempotencyKey);
            if (body is not null) request.Content = new StringContent(body, Encoding.UTF8, "application/json");
            try
            {
                using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                    cancellation).ConfigureAwait(false);
                try
                {
                    return await DecodeResponseAsync(response, expectedStatus, cancellation).ConfigureAwait(false);
                }
                catch (ElmPayApiException error) when (retrySafe && attempt + 1 < _attempts
                    && Retryable(error.StatusCode))
                {
                    // A fully validated problem response can be retried when the operation is safe.
                }
            }
            catch (HttpRequestException) when (retrySafe && attempt + 1 < _attempts) { }
            catch (TaskCanceledException) when (!cancellation.IsCancellationRequested
                && retrySafe && attempt + 1 < _attempts) { }
            await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(1000, 100 * (1 << attempt))),
                cancellation).ConfigureAwait(false);
        }
        throw new HttpRequestException("bounded retry exhausted");
    }

    private static async Task<ApiResponse> DecodeResponseAsync(HttpResponseMessage response,
        HttpStatusCode expectedStatus, CancellationToken cancellation)
    {
        var requestId = response.Headers.TryGetValues("X-Request-Id", out var ids)
            ? ids.FirstOrDefault() ?? "" : "";
        var content = response.Content
            ?? throw new InvalidResponseException("response content is missing", requestId);
        var mediaType = content.Headers.ContentType?.MediaType?.ToLowerInvariant() ?? "";
        if (mediaType != "application/json" && mediaType != "application/problem+json")
            throw new InvalidResponseException("Content-Type must be JSON", requestId);
        var raw = await ReadBoundedAsync(content, requestId, cancellation).ConfigureAwait(false);
        string text;
        try { text = new UTF8Encoding(false, true).GetString(raw); }
        catch (DecoderFallbackException error)
        { throw new InvalidResponseException("body is not valid UTF-8", requestId, error); }
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(text, new JsonDocumentOptions {
                AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 64 });
        }
        catch (JsonException error)
        { throw new InvalidResponseException("body is not strict JSON", requestId, error); }
        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new InvalidResponseException("JSON body must be an object", requestId);
            if (response.StatusCode == expectedStatus)
            {
                if (mediaType != "application/json")
                    throw new InvalidResponseException("success response must use application/json", requestId);
                return new ApiResponse(response.StatusCode,
                    DecodeCheckoutSession(document.RootElement, requestId), requestId);
            }
            var status = (int)response.StatusCode;
            if (status is >= 400 and <= 599)
            {
                if (mediaType != "application/problem+json")
                    throw new InvalidResponseException(
                        "error response must use application/problem+json", requestId);
                throw new ElmPayApiException(DecodeProblem(document.RootElement, status, requestId),
                    requestId);
            }
            throw new InvalidResponseException($"unexpected HTTP status {status}", requestId);
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpContent content, string requestId,
        CancellationToken cancellation)
    {
        if (content.Headers.ContentLength is > MaxResponseBytes)
            throw new ResponseTooLargeException(requestId);
        await using var stream = await content.ReadAsStreamAsync(cancellation).ConfigureAwait(false);
        using var destination = new MemoryStream();
        var buffer = new byte[64 * 1024];
        var total = 0;
        while (true)
        {
            var allowed = Math.Min(buffer.Length, MaxResponseBytes + 1 - total);
            var read = await stream.ReadAsync(buffer.AsMemory(0, allowed), cancellation).ConfigureAwait(false);
            if (read == 0) break;
            total += read;
            if (total > MaxResponseBytes) throw new ResponseTooLargeException(requestId);
            destination.Write(buffer, 0, read);
        }
        return destination.ToArray();
    }

    private static CheckoutSession DecodeCheckoutSession(JsonElement value, string requestId)
    {
        var id = RequiredString(value, "checkout_session_id", requestId);
        var expiresAt = RequiredString(value, "expires_at", requestId);
        var checkoutUrl = RequiredString(value, "checkout_url", requestId);
        if (!Rfc3339.IsMatch(expiresAt) || !DateTimeOffset.TryParse(expiresAt,
            CultureInfo.InvariantCulture, DateTimeStyles.None, out _))
            throw new InvalidResponseException("expires_at must be an RFC 3339 date-time", requestId);
        if (!Uri.TryCreate(checkoutUrl, UriKind.Absolute, out var parsed)
            || parsed.Scheme != Uri.UriSchemeHttps || string.IsNullOrWhiteSpace(parsed.Host))
            throw new InvalidResponseException("checkout_url must be an absolute HTTPS URL", requestId);
        return new CheckoutSession(id, expiresAt, checkoutUrl);
    }

    private static ApiProblem DecodeProblem(JsonElement value, int status, string requestId)
    {
        var type = RequiredString(value, "type", requestId);
        if (!Uri.TryCreate(type, UriKind.Absolute, out _))
            throw new InvalidResponseException("problem type must be an absolute URI", requestId);
        var title = RequiredString(value, "title", requestId);
        if (!value.TryGetProperty("status", out var rawStatus)
            || rawStatus.ValueKind != JsonValueKind.Number || !rawStatus.TryGetInt32(out var problemStatus)
            || problemStatus != status)
            throw new InvalidResponseException("problem status must match HTTP status", requestId);
        var code = RequiredString(value, "code", requestId);
        var traceId = RequiredString(value, "trace_id", requestId);
        string? detail = null;
        if (value.TryGetProperty("detail", out var rawDetail))
        {
            if (rawDetail.ValueKind != JsonValueKind.String)
                throw new InvalidResponseException("problem detail must be a string", requestId);
            detail = rawDetail.GetString();
        }
        return new ApiProblem(type, title, problemStatus, code, traceId, detail);
    }

    private static string RequiredString(JsonElement value, string name, string requestId)
    {
        if (!value.TryGetProperty(name, out var field) || field.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(field.GetString()))
            throw new InvalidResponseException($"field {name} must be a non-empty string", requestId);
        return field.GetString()!;
    }

    private static bool Retryable(HttpStatusCode code) =>
        (int)code is 408 or 429 || (int)code >= 500;

    public static bool VerifyWebhook(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> rawBody,
        string header, DateTimeOffset now, TimeSpan tolerance)
    {
        if (secret.Length < 32 || header is null || header.Length > 4096 || tolerance < TimeSpan.Zero
            || !double.IsFinite(tolerance.TotalMilliseconds)) return false;
        var parts = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var item in header.Split(','))
        {
            var separator = item.IndexOf('=');
            if (separator <= 0) return false;
            var key = item[..separator].Trim();
            var value = item[(separator + 1)..].Trim();
            if ((key != "t" && key != "v1") || value.Length == 0
                || value.Any(char.IsWhiteSpace) || !parts.TryAdd(key, value)) return false;
        }
        if (parts.Count != 2 || !parts.TryGetValue("t", out var rawTimestamp)
            || !Regex.IsMatch(rawTimestamp, "^[0-9]{1,19}$", RegexOptions.CultureInvariant)
            || !parts.TryGetValue("v1", out var signature)
            || !Regex.IsMatch(signature, "^[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant)
            || !long.TryParse(rawTimestamp, NumberStyles.None, CultureInfo.InvariantCulture, out var timestamp)
            || timestamp < 0) return false;
        DateTimeOffset signedAt;
        try { signedAt = DateTimeOffset.FromUnixTimeSeconds(timestamp); }
        catch (ArgumentOutOfRangeException) { return false; }
        if ((now - signedAt).Duration() > tolerance) return false;
        byte[] supplied;
        try { supplied = Convert.FromBase64String(signature.Replace('-', '+').Replace('_', '/')
            .PadRight((signature.Length + 3) / 4 * 4, '=')); }
        catch (FormatException) { return false; }
        if (supplied.Length != 32) return false;
        using var hmac = new HMACSHA256(secret.ToArray());
        var prefix = Encoding.ASCII.GetBytes(timestamp + ".");
        var message = new byte[prefix.Length + rawBody.Length];
        prefix.CopyTo(message, 0);
        rawBody.CopyTo(message.AsSpan(prefix.Length));
        return CryptographicOperations.FixedTimeEquals(hmac.ComputeHash(message), supplied);
    }
}
