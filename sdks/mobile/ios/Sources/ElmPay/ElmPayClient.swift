import Foundation
import CryptoKit

public protocol ElmPayTransport: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}
extension URLSession: ElmPayTransport {
    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await data(for: request)
        guard let http = response as? HTTPURLResponse else { throw ElmPayError.invalidResponse }
        return (data, http)
    }
}
public protocol DeviceAttestationProvider: Sendable { func assertion(challenge: Data) async throws -> String }
public protocol PaymentMethodLauncher: Sendable { func launch(method: String, launchURL: URL) async throws }

public enum ElmPayError: Error { case invalidConfiguration, invalidResponse, retryExhausted, untrustedDeepLink }
public struct CreateCheckoutRequest: Encodable, Sendable {
    public let businessOrderNo: String, amount: Int64, currency: String, returnRouteId: String?
    public init(businessOrderNo: String, amount: Int64, currency: String, returnRouteId: String? = nil) {
        self.businessOrderNo = businessOrderNo; self.amount = amount; self.currency = currency; self.returnRouteId = returnRouteId
    }
    enum CodingKeys: String, CodingKey { case businessOrderNo = "business_order_no"; case amount, currency; case returnRouteId = "return_route_id" }
}
public struct ConfirmCheckoutRequest: Encodable, Sendable {
    public let paymentMethodType: String, paymentMethodReference: String?, fingerprint: String?
    public init(paymentMethodType: String, paymentMethodReference: String? = nil, fingerprint: String? = nil) {
        self.paymentMethodType = paymentMethodType; self.paymentMethodReference = paymentMethodReference; self.fingerprint = fingerprint
    }
    enum CodingKeys: String, CodingKey { case paymentMethodType = "payment_method_type"; case paymentMethodReference = "payment_method_reference"; case fingerprint }
}
public struct CheckoutSession: Codable, Sendable {
    public let checkoutSessionId: String, status: String
    enum CodingKeys: String, CodingKey { case checkoutSessionId = "checkout_session_id"; case status }
}

public actor ElmPayClient {
    private let baseURL: URL, token: String, projectId: String, transport: ElmPayTransport, attempts: Int
    public init(baseURL: URL, bearerToken: String, projectId: String, transport: ElmPayTransport = URLSession.shared, maximumAttempts: Int = 3) throws {
        guard baseURL.scheme == "https", !bearerToken.isEmpty, !projectId.isEmpty, projectId.count <= 64, (1...5).contains(maximumAttempts) else { throw ElmPayError.invalidConfiguration }
        self.baseURL = baseURL; token = bearerToken; self.projectId = projectId; self.transport = transport; attempts = maximumAttempts
    }
    public func createSession(_ value: CreateCheckoutRequest, attestation: DeviceAttestationProvider) async throws -> CheckoutSession {
        guard value.amount > 0, !value.businessOrderNo.isEmpty, !value.currency.isEmpty else { throw ElmPayError.invalidConfiguration }
        let idempotencyKey = UUID().uuidString, challenge = Data(UUID().uuidString.utf8)
        let assertion = try await attestation.assertion(challenge: challenge)
        guard !assertion.isEmpty else { throw ElmPayError.invalidConfiguration }
        let data = try JSONEncoder().encode(value)
        return try await send(path: "/v1/checkout-sessions", method: "POST", body: data,
                              idempotencyKey: idempotencyKey, extraHeaders: ["X-Device-Attestation": assertion])
    }
    public func retrieveSession(id: String) async throws -> CheckoutSession {
        try await send(path: "/v1/checkout-sessions/\(pathSegment(id))", method: "GET", body: nil, idempotencyKey: nil)
    }
    public func confirmSession(id: String, request: ConfirmCheckoutRequest) async throws -> CheckoutSession {
        guard !request.paymentMethodType.isEmpty else { throw ElmPayError.invalidConfiguration }
        return try await send(path: "/v1/checkout-sessions/\(pathSegment(id))/confirm", method: "POST",
                              body: try JSONEncoder().encode(request), idempotencyKey: UUID().uuidString)
    }
    public func validateDeepLink(_ url: URL, expectedScheme: String, expectedHost: String, expectedState: String) throws -> String {
        let values = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems
        let state = values?.first(where: { $0.name == "state" })?.value ?? ""
        guard url.scheme == expectedScheme, url.host == expectedHost,
              Data(state.utf8).constantTimeEquals(Data(expectedState.utf8)),
              let session = values?.first(where: { $0.name == "session" })?.value, !session.isEmpty else { throw ElmPayError.untrustedDeepLink }
        return session // caller must retrieve server state; this is not payment success
    }
    private func send(path: String, method: String, body: Data?, idempotencyKey: String?, extraHeaders: [String: String] = [:]) async throws -> CheckoutSession {
        for attempt in 0..<attempts {
            var request = URLRequest(url: URL(string: path, relativeTo: baseURL)!); request.httpMethod = method; request.httpBody = body
            request.timeoutInterval = 5; request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization"); request.setValue("application/json", forHTTPHeaderField: "Accept"); request.setValue(projectId, forHTTPHeaderField: "X-Project-Id")
            if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
            if let idempotencyKey { request.setValue(idempotencyKey, forHTTPHeaderField: "Idempotency-Key") }
            extraHeaders.forEach { request.setValue($1, forHTTPHeaderField: $0) }
            do {
                let (data, response) = try await transport.send(request)
                if (200..<300).contains(response.statusCode) { let decoder = JSONDecoder(); return try decoder.decode(CheckoutSession.self, from: data) }
                let retrySafe = idempotencyKey != nil || method == "GET"
                if !retrySafe || attempt + 1 == attempts || !(response.statusCode == 408 || response.statusCode == 429 || response.statusCode >= 500) { throw ElmPayError.invalidResponse }
            } catch {
                if idempotencyKey == nil && method != "GET" || attempt + 1 == attempts { throw error }
            }
            try await Task.sleep(nanoseconds: UInt64(min(1000, 100 << attempt)) * 1_000_000)
        }
        throw ElmPayError.retryExhausted
    }
    private func pathSegment(_ value: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? ""
    }
}
private extension Data {
    func constantTimeEquals(_ other: Data) -> Bool {
        guard count == other.count else { return false }; return zip(self, other).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }
}
