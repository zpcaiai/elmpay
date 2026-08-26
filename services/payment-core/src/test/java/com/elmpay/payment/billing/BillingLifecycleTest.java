package com.elmpay.payment.billing;
import static org.junit.jupiter.api.Assertions.*;
import java.time.*; import java.util.*; import org.junit.jupiter.api.Test;
class BillingLifecycleTest {
 @Test void mandateRejectsPanAndEnforcesScope() {
  var mandates=new MandateService(Clock.systemUTC());
  assertThrows(SecurityException.class,()->mandates.create("t","c","psp","m","4111111111111111","renewal",100,"USD","digest"));
  var m=mandates.create("t","c","psp","m","pm_tok_opaque","renewal",100,"USD","digest");
  mandates.authorize("t",m.id(),"renewal",100,"USD"); assertThrows(SecurityException.class,()->mandates.authorize("t",m.id(),"other",1,"USD"));
  mandates.revoke("t",m.id()); assertThrows(SecurityException.class,()->mandates.authorize("t",m.id(),"renewal",1,"USD"));
 }
 @Test void prorationUsesHalfEvenIntegerArithmetic() {
  var adjustment=new ProrationCalculator().calculate(1001,2001,1,2);
  assertEquals(500,adjustment.oldUnusedCreditMinor()); assertEquals(1000,adjustment.newRemainingChargeMinor()); assertEquals(500,adjustment.netDebitMinor());
 }
 @Test void usageIsIdempotentAndUnknownRenewalDoesNotAdvancePeriod() {
  var now=Instant.parse("2026-08-26T00:00:00Z"); var service=new SubscriptionService(Clock.fixed(now,ZoneOffset.UTC));
  service.addPlan(new SubscriptionService.Plan("plan","t",100,"USD",Duration.ofDays(30),Duration.ZERO,true));
  var sub=service.subscribe("t","c","plan","m"); service.recordUsage("t",sub.id(),"u1",4); service.recordUsage("t",sub.id(),"u1",4);
  assertEquals(4,service.get("t",sub.id()).usage()); var before=service.get("t",sub.id());
  assertEquals(before,service.renewalResult("t",sub.id(),false,false));
 }
 @Test void dunningUnknownWaitsForQueryWithoutDoubleCountingAttempt() {
  var service=new DunningService(Clock.systemUTC(),new DunningService.Policy(List.of(Duration.ofSeconds(1),Duration.ofSeconds(2)),Duration.ofDays(1)));
  var value=service.open("t","s"); value=service.recordAttempt("t",value.id(),false,false);
  assertEquals(DunningService.Status.WAITING_PROVIDER_QUERY,value.status()); assertEquals(1,value.attempts());
  value=service.resumeAfterQuery("t",value.id(),true); assertEquals(DunningService.Status.SCHEDULED,value.status()); assertEquals(1,value.attempts());
 }
}
