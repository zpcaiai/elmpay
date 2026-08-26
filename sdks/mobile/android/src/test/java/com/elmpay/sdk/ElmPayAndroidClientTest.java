package com.elmpay.sdk;
import static org.junit.jupiter.api.Assertions.*;
import java.net.URI; import java.nio.charset.StandardCharsets; import java.time.Duration; import java.util.*; import java.util.concurrent.atomic.AtomicInteger; import org.junit.jupiter.api.Test;
class ElmPayAndroidClientTest {
 @Test void createRetriesWithStableIdempotencyAndDeepLinkDoesNotClaimSuccess() throws Exception {
  var calls=new AtomicInteger(); var observed=new ArrayList<ElmPayAndroidClient.Request>(); String project="10000000-0000-4000-8000-000000000002";
  var client=new ElmPayAndroidClient(URI.create("https://api.example/"),"token",project,request->{observed.add(request);assertNotNull(request.headers().get("idempotency-key")); return new ElmPayAndroidClient.Response(calls.incrementAndGet()<2?503:200,new byte[0]);},3,Duration.ofSeconds(1));
  assertEquals(200,client.createSession(new ElmPayAndroidClient.CheckoutRequest("order-1",1250,"USD","complete"),challenge->"assertion").status()); assertEquals(2,calls.get());
  var create=observed.get(0); assertEquals("/v1/checkout-sessions",create.uri().getRawPath()); assertEquals(project,create.headers().get("x-project-id")); assertEquals("assertion",create.headers().get("x-device-attestation"));
  String json=new String(create.body(),StandardCharsets.UTF_8); assertEquals("{\"business_order_no\":\"order-1\",\"amount\":1250,\"currency\":\"USD\",\"return_route_id\":\"complete\"}",json); assertFalse(json.contains("amount_minor")); assertFalse(json.contains("return_uri"));
  observed.clear(); client.retrieveSession("session/unsafe"); client.confirmSession("session-1",new ElmPayAndroidClient.ConfirmRequest("stripe_card","psp://tok/1","fp"));
  assertEquals("/v1/checkout-sessions/session%2Funsafe",observed.get(0).uri().getRawPath()); assertEquals(project,observed.get(0).headers().get("x-project-id")); assertEquals("/v1/checkout-sessions/session-1/confirm",observed.get(1).uri().getRawPath()); assertTrue(new String(observed.get(1).body(),StandardCharsets.UTF_8).contains("\"payment_method_type\":\"stripe_card\""));
  assertEquals("s1",client.validateDeepLink(URI.create("elmpay://return?state=opaque&session=s1"),"elmpay","return","opaque"));
  assertThrows(SecurityException.class,()->client.validateDeepLink(URI.create("elmpay://evil?state=opaque&session=s1"),"elmpay","return","opaque"));
 }
}
