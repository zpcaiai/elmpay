import 'dart:convert';

import 'package:elmpay/elmpay_client.dart';
import 'package:test/test.dart';

final class RecordingTransport implements Transport {
  final requests = <Request>[];
  var attempts = 0;

  @override
  Future<Response> send(Request request) async {
    requests.add(request);
    attempts += 1;
    if (attempts == 1) return const Response(503, <int>[]);
    return Response(200, utf8.encode(
      '{"checkout_session_id":"session-1","status":"OPEN"}'));
  }
}

final class Attestation implements DeviceAttestationProvider {
  @override
  Future<String> assertion(List<int> challenge) async {
    expect(challenge.length, 32);
    return 'device-assertion';
  }
}

final class Launcher implements PaymentMethodLauncher {
  final calls = <(String, Uri)>[];

  @override
  Future<void> launch(String method, Uri uri) async => calls.add((method, uri));
}

void main() {
  const project = '10000000-0000-4000-8000-000000000002';

  test('create retries with one idempotency key and preserves device assertion', () async {
    final transport = RecordingTransport();
    final client = ElmPayClient(Uri.parse('https://api.example/'), 'placeholder-token',
      project, transport);
    final session = await client.createSession(
      const CheckoutRequest('order-1', 1250, 'USD', returnRouteId: 'complete'),
      Attestation(), idempotencyKey: 'stable-create-key-0001');
    expect(session.checkoutSessionId, 'session-1');
    expect(transport.requests, hasLength(2));
    expect(transport.requests.map((value) => value.headers['idempotency-key']).toSet(),
      {'stable-create-key-0001'});
    expect(transport.requests.first.headers['x-device-attestation'], 'device-assertion');
    expect(transport.requests.first.headers['x-elmpay-device-class'], 'FLUTTER');
    final body = jsonDecode(utf8.decode(transport.requests.first.body!)) as Map;
    expect(body, {'business_order_no': 'order-1', 'amount': 1250,
      'currency': 'USD', 'return_route_id': 'complete'});
    expect(body.containsKey('amount_minor'), isFalse);
  });

  test('deep links and provider launch never infer success', () async {
    final transport = RecordingTransport()..attempts = 1;
    final client = ElmPayClient(Uri.parse('https://api.example/'), 'placeholder-token',
      project, transport, maximumAttempts: 1);
    expect(client.validateDeepLink(Uri.parse('elmpay://return?state=opaque&session=s1'),
      'elmpay', 'return', 'opaque'), 's1');
    expect(() => client.validateDeepLink(
      Uri.parse('elmpay://evil?state=opaque&session=s1'), 'elmpay', 'return', 'opaque'),
      throwsStateError);
    final launcher = Launcher();
    await client.launchPaymentMethod('wechat_app', Uri.parse('weixin://pay/reference'), launcher);
    expect(launcher.calls.single.$1, 'wechat_app');
    expect(() => client.launchPaymentMethod('card',
      Uri.parse('http://evil.example/pay'), launcher), throwsStateError);
  });
}
