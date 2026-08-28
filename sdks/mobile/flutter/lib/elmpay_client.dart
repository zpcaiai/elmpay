import 'dart:async';
import 'dart:convert';
import 'dart:math';

abstract interface class Transport { Future<Response> send(Request request); }
abstract interface class DeviceAttestationProvider {
  Future<String> assertion(List<int> challenge);
}
abstract interface class PaymentMethodLauncher {
  Future<void> launch(String method, Uri uri);
}

final class Request {
  final String method;
  final Uri uri;
  final Map<String, String> headers;
  final List<int>? body;
  const Request(this.method, this.uri, this.headers, this.body);
}

final class Response {
  final int status;
  final List<int> body;
  const Response(this.status, this.body);
}

final class CheckoutRequest {
  final String businessOrderNo;
  final int amount;
  final String currency;
  final String? returnRouteId;
  const CheckoutRequest(this.businessOrderNo, this.amount, this.currency,
      {this.returnRouteId});

  Map<String, Object> toJson() => <String, Object>{
        'business_order_no': businessOrderNo,
        'amount': amount,
        'currency': currency,
        if (returnRouteId != null) 'return_route_id': returnRouteId!,
      };
}

final class ConfirmRequest {
  final String paymentMethodType;
  final String? paymentMethodReference;
  final String? fingerprint;
  const ConfirmRequest(this.paymentMethodType,
      {this.paymentMethodReference, this.fingerprint});

  Map<String, Object> toJson() => <String, Object>{
        'payment_method_type': paymentMethodType,
        if (paymentMethodReference != null)
          'payment_method_reference': paymentMethodReference!,
        if (fingerprint != null) 'fingerprint': fingerprint!,
      };
}

final class CheckoutSession {
  final String checkoutSessionId;
  final String status;
  final String? paymentIntentId;
  final int? amount;
  final String? currency;
  const CheckoutSession(this.checkoutSessionId, this.status,
      {this.paymentIntentId, this.amount, this.currency});

  factory CheckoutSession.fromJson(Map<String, dynamic> value) {
    final id = value['checkout_session_id'] ?? value['id'];
    final status = value['status'];
    if (id is! String || status is! String) {
      throw const FormatException('checkout session response is invalid');
    }
    return CheckoutSession(id, status,
        paymentIntentId: value['payment_intent_id'] as String?,
        amount: value['amount'] is int ? value['amount'] as int : null,
        currency: value['currency'] as String?);
  }
}

final class ElmPayClient {
  final Uri baseUri;
  final String bearerToken;
  final String projectId;
  final Transport transport;
  final int maximumAttempts;

  ElmPayClient(this.baseUri, this.bearerToken, this.projectId, this.transport,
      {this.maximumAttempts = 3}) {
    if (baseUri.scheme != 'https' || bearerToken.isEmpty ||
        !_uuidPattern.hasMatch(projectId) ||
        maximumAttempts < 1 || maximumAttempts > 5) {
      throw ArgumentError('secure configuration required');
    }
  }

  Future<CheckoutSession> createSession(CheckoutRequest payload,
      DeviceAttestationProvider attestation,
      {String? idempotencyKey}) async {
    if (payload.amount <= 0 || payload.businessOrderNo.isEmpty ||
        payload.currency.isEmpty) {
      throw ArgumentError('invalid checkout request');
    }
    final random = Random.secure();
    final challenge = List<int>.generate(32, (_) => random.nextInt(256));
    final assertion = await attestation.assertion(challenge);
    if (assertion.isEmpty) throw StateError('device assertion missing');
    return _send('POST', '/v1/checkout-sessions',
        utf8.encode(jsonEncode(payload.toJson())),
        idempotencyKey ?? _opaqueId(random),
        extraHeaders: {'x-device-attestation': assertion});
  }

  Future<CheckoutSession> retrieveSession(String id) => _send(
      'GET', '/v1/checkout-sessions/${Uri.encodeComponent(id)}', null, null);

  Future<CheckoutSession> confirmSession(String id, ConfirmRequest payload,
      {String? idempotencyKey}) {
    if (payload.paymentMethodType.isEmpty) {
      throw ArgumentError('payment method type required');
    }
    return _send(
        'POST',
        '/v1/checkout-sessions/${Uri.encodeComponent(id)}/confirm',
        utf8.encode(jsonEncode(payload.toJson())),
        idempotencyKey ?? _opaqueId(Random.secure()));
  }

  Future<void> launchPaymentMethod(String method, Uri launchUri,
      PaymentMethodLauncher launcher) {
    const schemes = {'https', 'weixin', 'alipay', 'paypal'};
    if (!_methodPattern.hasMatch(method) || !schemes.contains(launchUri.scheme) ||
        launchUri.userInfo.isNotEmpty || launchUri.fragment.isNotEmpty) {
      throw StateError('untrusted provider launch URI');
    }
    return launcher.launch(method, launchUri);
  }

  String validateDeepLink(Uri uri, String expectedScheme, String expectedHost,
      String expectedState) {
    final state = uri.queryParameters['state'] ?? '';
    if (uri.scheme != expectedScheme || uri.host != expectedHost ||
        !_constantTimeEqual(state, expectedState)) {
      throw StateError('untrusted deep link');
    }
    final session = uri.queryParameters['session'];
    if (session == null || session.isEmpty) throw StateError('missing session');
    return session;
  }

  Future<CheckoutSession> _send(String method, String path, List<int>? body,
      String? idempotencyKey,
      {Map<String, String> extraHeaders = const {}}) async {
    final retrySafe = method == 'GET' || idempotencyKey != null;
    for (var attempt = 0; attempt < maximumAttempts; attempt++) {
      try {
        final headers = <String, String>{
          'authorization': 'Bearer $bearerToken',
          'accept': 'application/json',
          'x-project-id': projectId,
          'x-elmpay-device-class': 'FLUTTER',
          if (body != null) 'content-type': 'application/json',
          if (idempotencyKey != null) 'idempotency-key': idempotencyKey,
          ...extraHeaders,
        };
        final response = await transport
            .send(Request(method, baseUri.resolve(path), headers, body))
            .timeout(const Duration(seconds: 5));
        if (response.status >= 200 && response.status < 300) {
          final value = jsonDecode(utf8.decode(response.body));
          if (value is! Map<String, dynamic>) {
            throw const FormatException('response is not an object');
          }
          return CheckoutSession.fromJson(value);
        }
        if (!retrySafe || attempt + 1 == maximumAttempts ||
            !_retryable(response.status)) {
          throw StateError('request rejected: ${response.status}');
        }
      } catch (_) {
        if (!retrySafe || attempt + 1 == maximumAttempts) rethrow;
      }
      await Future<void>.delayed(
          Duration(milliseconds: min(1000, 100 * (1 << attempt))));
    }
    throw StateError('bounded retry exhausted');
  }

  static bool _retryable(int status) =>
      status == 408 || status == 429 || status >= 500;
  static String _opaqueId(Random random) => base64Url
      .encode(List<int>.generate(24, (_) => random.nextInt(256)))
      .replaceAll('=', '');
  static bool _constantTimeEqual(String left, String right) {
    var difference = left.length ^ right.length;
    for (var index = 0; index < min(left.length, right.length); index++) {
      difference |= left.codeUnitAt(index) ^ right.codeUnitAt(index);
    }
    return difference == 0;
  }
}

final _uuidPattern = RegExp(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
    caseSensitive: false);
final _methodPattern = RegExp(r'^[a-z0-9][a-z0-9._-]{0,63}$');
