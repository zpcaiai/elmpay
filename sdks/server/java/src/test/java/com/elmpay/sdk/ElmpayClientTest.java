package com.elmpay.sdk;
import static org.junit.jupiter.api.Assertions.*;
import java.net.URI; import java.nio.charset.StandardCharsets; import java.time.*; import java.util.*; import javax.crypto.Mac; import javax.crypto.spec.SecretKeySpec; import org.junit.jupiter.api.Test;
class ElmpayClientTest {
 @Test void serializesCanonicalCheckoutRequests() throws Exception {
  List<ElmpayClient.SdkRequest> calls=new ArrayList<>(); String project="10000000-0000-4000-8000-000000000002";
  var client=new ElmpayClient(URI.create("https://api.example/"),"token",project,Duration.ofSeconds(1),1,(request,timeout)->{calls.add(request);return new ElmpayClient.ApiResponse(200,"{}","r1");});
  client.createCheckoutSession(new ElmpayClient.CheckoutRequest("order-1",1250,"USD","complete"),"create-idempotency-0001");
  client.getCheckoutSession("session/unsafe");
  client.confirmCheckoutSession("session-1",new ElmpayClient.ConfirmRequest("stripe_card","psp://tok/1","fp"),"confirm-idempotency-001");
  assertEquals(List.of("/v1/checkout-sessions","/v1/checkout-sessions/session%2Funsafe","/v1/checkout-sessions/session-1/confirm"),calls.stream().map(v->v.uri().getRawPath()).toList());
  calls.forEach(v->assertEquals(project,v.headers().get("x-project-id")));
  String create=calls.get(0).body(); assertEquals("{\"business_order_no\":\"order-1\",\"amount\":1250,\"currency\":\"USD\",\"return_route_id\":\"complete\"}",create);
  assertFalse(create.contains("project_id")); assertFalse(create.contains("order_reference")); assertFalse(create.contains("amount_minor")); assertFalse(create.contains("return_uri"));
  assertEquals("{\"payment_method_type\":\"stripe_card\",\"payment_method_reference\":\"psp://tok/1\",\"fingerprint\":\"fp\"}",calls.get(2).body());
 }
 @Test void verifiesFreshRawWebhookBytes() throws Exception {
  byte[] secret=new byte[32], body="{\"ok\":true}".getBytes(StandardCharsets.UTF_8); long timestamp=1700000000L;
  Mac mac=Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(secret,"HmacSHA256")); mac.update(Long.toString(timestamp).getBytes(StandardCharsets.US_ASCII)); mac.update((byte)'.');
  String signature=Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(body)); String header="t="+timestamp+",v1="+signature;
  var clock=Clock.fixed(Instant.ofEpochSecond(timestamp),ZoneOffset.UTC); assertTrue(ElmpayClient.verifyWebhook(secret,body,header,clock,Duration.ofMinutes(5)));
  assertFalse(ElmpayClient.verifyWebhook(secret,"{}".getBytes(StandardCharsets.UTF_8),header,clock,Duration.ofMinutes(5)));
 }
}
