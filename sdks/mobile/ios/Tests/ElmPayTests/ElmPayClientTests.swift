import Foundation
import XCTest
@testable import ElmPay

actor RecordingTransport: ElmPayTransport {
    private var values: [URLRequest] = []
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        values.append(request)
        let data = Data(#"{"checkout_session_id":"session-1","status":"OPEN"}"#.utf8)
        return (data, HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                     headerFields: [:])!)
    }
    func recorded() -> [URLRequest] { values }
}
actor TerminalTransport: ElmPayTransport {
    private var count = 0
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        count += 1
        return (Data(), HTTPURLResponse(url: request.url!, statusCode: 400, httpVersion: nil,
                                       headerFields: [:])!)
    }
    func attempts() -> Int { count }
}
struct Attestation: DeviceAttestationProvider {
    func assertion(challenge: Data) async throws -> String { "device-assertion" }
}
actor Launcher: PaymentMethodLauncher {
    private var values: [(String, URL)] = []
    func launch(method: String, launchURL: URL) async throws { values.append((method, launchURL)) }
    func recorded() -> [(String, URL)] { values }
}

@MainActor final class ElmPayClientTests: XCTestCase {
    func testCanonicalCreateGetAndConfirm() async throws {
        let transport = RecordingTransport()
        let project = "10000000-0000-4000-8000-000000000002"
        let client = try ElmPayClient(baseURL: URL(string: "https://api.example/")!,
                                      bearerToken: "token", projectId: project,
                                      transport: transport, maximumAttempts: 1)
        _ = try await client.createSession(CreateCheckoutRequest(businessOrderNo: "order-1",
            amount: 1250, currency: "USD", returnRouteId: "complete"), attestation: Attestation())
        _ = try await client.retrieveSession(id: "session/unsafe")
        _ = try await client.confirmSession(id: "session-1", request: ConfirmCheckoutRequest(
            paymentMethodType: "stripe_card", paymentMethodReference: "psp://tok/1", fingerprint: "fp"))
        let requests = await transport.recorded()
        XCTAssertEqual(requests.map { $0.url!.absoluteString }, [
            "https://api.example/v1/checkout-sessions",
            "https://api.example/v1/checkout-sessions/session%2Funsafe",
            "https://api.example/v1/checkout-sessions/session-1/confirm"])
        requests.forEach { XCTAssertEqual($0.value(forHTTPHeaderField: "X-Project-Id"), project) }
        requests.forEach { XCTAssertEqual($0.value(forHTTPHeaderField: "X-ElmPay-Device-Class"), "IOS") }
        XCTAssertEqual(requests[0].value(forHTTPHeaderField: "X-Device-Attestation"), "device-assertion")
        let create = try XCTUnwrap(JSONSerialization.jsonObject(with: requests[0].httpBody!) as? [String: Any])
        XCTAssertEqual(create["business_order_no"] as? String, "order-1")
        XCTAssertEqual((create["amount"] as? NSNumber)?.int64Value, 1250)
        ["project_id", "order_reference", "amount_minor", "return_uri", "device_assertion"].forEach {
            XCTAssertNil(create[$0])
        }
        let confirm = try XCTUnwrap(JSONSerialization.jsonObject(with: requests[2].httpBody!) as? [String: Any])
        XCTAssertEqual(confirm["payment_method_type"] as? String, "stripe_card")
    }

    func testDeepLinkNeverClaimsPaymentSuccess() async throws {
        let client = try ElmPayClient(baseURL: URL(string: "https://api.example/")!, bearerToken: "token",
            projectId: "10000000-0000-4000-8000-000000000002", transport: RecordingTransport(), maximumAttempts: 1)
        let session = try await client.validateDeepLink(URL(string: "elmpay://return?state=opaque&session=s1")!,
            expectedScheme: "elmpay", expectedHost: "return", expectedState: "opaque")
        XCTAssertEqual(session, "s1")
        let launcher = Launcher()
        try await client.launchPaymentMethod(method: "apple_pay",
            launchURL: URL(string: "https://wallet.example/authorize")!, launcher: launcher)
        let launched = await launcher.recorded()
        XCTAssertEqual(launched.first?.0, "apple_pay")
        await XCTAssertThrowsErrorAsync(try await client.launchPaymentMethod(method: "card",
            launchURL: URL(string: "http://evil.example/pay")!, launcher: launcher))
    }

    func testTerminalClientErrorIsNeverRetried() async throws {
        let transport = TerminalTransport()
        let client = try ElmPayClient(baseURL: URL(string: "https://api.example/")!,
            bearerToken: "token", projectId: "10000000-0000-4000-8000-000000000002",
            transport: transport, maximumAttempts: 5)
        await XCTAssertThrowsErrorAsync(try await client.retrieveSession(id: "session-1"))
        let attempts = await transport.attempts()
        XCTAssertEqual(attempts, 1)
    }
}

@MainActor private func XCTAssertThrowsErrorAsync<T>(_ expression: @autoclosure () async throws -> T,
                                                      file: StaticString = #filePath,
                                                      line: UInt = #line) async {
    do {
        _ = try await expression()
        XCTFail("expected error", file: file, line: line)
    } catch {}
}
