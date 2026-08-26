package com.elmpay.payment.refund;
import static org.junit.jupiter.api.Assertions.*;
import java.time.*; import java.util.concurrent.*; import org.junit.jupiter.api.Test;
class RefundServiceTest {
 @Test void reservesAmountAndRequiresFourEyes() {
  var service=new RefundService(Clock.systemUTC(),(capture,request)->RefundService.RiskDecision.MANUAL_REVIEW,
    new RefundService.Provider(){public RefundService.ProviderResult submit(RefundService.Refund r){return new RefundService.ProviderResult(RefundService.ProviderOutcome.SUCCEEDED,"p1");} public RefundService.ProviderResult query(RefundService.Refund r){throw new AssertionError();}});
  service.registerCapture(new RefundService.Capture("t","pay",1000,"USD"));
  var refund=service.request("t","pay",new RefundService.Request("i1",700,"alice","customer request"));
  assertEquals(300,service.remainingRefundable("t","pay"));
  assertThrows(SecurityException.class,()->service.approve("t",refund.id(),"alice","same actor"));
  assertEquals(RefundService.Status.SUCCEEDED,service.approve("t",refund.id(),"bob","ticket-1").status());
  assertThrows(IllegalStateException.class,()->service.request("t","pay",new RefundService.Request("i2",301,"carol","too much")));
 }
 @Test void transportFailureRemainsUnknownUntilQuery() {
  var service=new RefundService(Clock.systemUTC(),(c,r)->RefundService.RiskDecision.AUTO_APPROVE,
    new RefundService.Provider(){public RefundService.ProviderResult submit(RefundService.Refund r){throw new RuntimeException("timeout");} public RefundService.ProviderResult query(RefundService.Refund r){return new RefundService.ProviderResult(RefundService.ProviderOutcome.SUCCEEDED,"confirmed");}});
  service.registerCapture(new RefundService.Capture("t","p",100,"USD")); var refund=service.request("t","p",new RefundService.Request("i",100,"a","r"));
 assertEquals(RefundService.Status.UNKNOWN,refund.status()); assertEquals(RefundService.Status.SUCCEEDED,service.recoverUnknown("t",refund.id(),"worker").status());
 }
 @Test void disputesRequireVerifiedEventsAndVersionEvidence() {
  var now=Instant.now(); var service=new DisputeService(Clock.fixed(now,ZoneOffset.UTC));
  var unverified=new DisputeService.ProviderEvent("t","e1","d1","p",100,"USD",now.plusSeconds(60),false);
  assertThrows(SecurityException.class,()->service.ingest(unverified));
  var verified=new DisputeService.ProviderEvent("t","e1","d1","p",100,"USD",now.plusSeconds(60),true);
  var dispute=service.ingest(verified); dispute=service.submitEvidence("t",dispute.providerDisputeId(),"0".repeat(64),"application/pdf","alice");
  assertEquals(1,dispute.evidence().getFirst().revision()); assertEquals(dispute,service.ingest(verified));
 }
}
