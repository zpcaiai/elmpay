package com.elmpay.reconciliation;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets; import java.time.*; import java.util.*; import org.junit.jupiter.api.Test;
class ReconciliationTest {
 @Test void statementParserIsStrictAndVersionReady() {
  var dataSource=(javax.sql.DataSource)java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{javax.sql.DataSource.class},(proxy,method,args)->{throw new UnsupportedOperationException();});
  var intake=new StatementIngestionService(dataSource,Clock.systemUTC(),4096,10);
  var csv="external_reference,amount_minor,currency,event_type,occurred_at\n\"order,1\",100,usd,CAPTURE,2026-08-26T00:00:00Z\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
  var rows=intake.parse(csv); assertEquals("order,1",rows.getFirst().externalReference()); assertEquals("USD",rows.getFirst().currency());
  assertThrows(IllegalArgumentException.class,()->intake.parse("external_reference,amount_minor\no,1\n".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
 }
 @Test void fourSourcesMustAllTie() {
  var now=Instant.parse("2026-08-26T00:00:00Z"); var facts=new ArrayList<ReconciliationEngine.Fact>();
  for(var source:ReconciliationEngine.Source.values()) facts.add(new ReconciliationEngine.Fact(source,"t","order","CAPTURE",100,"USD",now,"d"+source));
  var engine=new ReconciliationEngine(); assertEquals(ReconciliationEngine.Outcome.MATCHED,engine.reconcile("t",now,facts).matches().getFirst().outcome());
  facts.set(3,new ReconciliationEngine.Fact(ReconciliationEngine.Source.BANK,"t","order","CAPTURE",99,"USD",now,"x"));
  assertEquals(ReconciliationEngine.Outcome.AMOUNT_MISMATCH,engine.reconcile("t",now,facts).matches().getFirst().outcome());
 }
 @Test void adjustmentRequiresDistinctApproverAndLedgerTransaction() {
  var flow=new ExceptionWorkflow(Clock.systemUTC()); var ticket=flow.open("t","m","amount mismatch"); ticket=flow.claim("t",ticket.id(),"alice"); ticket=flow.proposeAdjustment("t",ticket.id(),"alice",1,"USD","rounding");
  var id=ticket.id(); var ledgerId=UUID.randomUUID().toString(); assertThrows(SecurityException.class,()->flow.approve("t",id,"alice",ledgerId,"same actor"));
  assertEquals(ExceptionWorkflow.Status.RESOLVED,flow.approve("t",id,"bob",ledgerId,"approved").status());
 }
 @Test void signedReportDetectsTampering() {
  var service=new FinancialReportService(new TestSigner()); var from=Instant.EPOCH; var to=from.plusSeconds(10);
  var report=service.generate("t",from,to,List.of(new FinancialReportService.Fact("1","t",FinancialReportService.Type.CAPTURE,100,"USD",from),new FinancialReportService.Fact("2","t",FinancialReportService.Type.FEE,3,"USD",from)));
  assertEquals("test-kms-v1",report.signingKeyVersion()); assertEquals(97,report.byCurrency().get("USD").netRevenueMinor()); assertTrue(service.verify(report)); var tampered=new FinancialReportService.Report(report.tenantId(),report.from(),report.to(),Map.of("USD",new FinancialReportService.Totals(101,3,0,0,0,0,98)),report.sourceDigest(),report.signingKeyVersion(),report.manifestSignature());
  assertFalse(service.verify(tampered));
 }
 @Test void signerReadinessFailsClosed() {
  assertThrows(IllegalStateException.class,()->new FinancialReportService(new ExportManifestSigner(){
   public Signature sign(byte[] value){throw new AssertionError();}
   public boolean verify(String version,byte[] value,String signature){return false;}
   public boolean ready(){return false;}
  }));
 }
 @Test void migrationUsesCanonicalRunAndFailClosedTenantPolicies() throws Exception {
  try(var input=getClass().getResourceAsStream("/db/migration/V076__reconciliation.sql")) {
   assertNotNull(input); var sql=new String(input.readAllBytes(),StandardCharsets.UTF_8);
   assertTrue(sql.contains("business_date text NOT NULL")); assertTrue(sql.contains("source_file_digest text NOT NULL"));
   assertTrue(sql.contains("recon_run_source_unique")); assertEquals(8,count(sql,"FORCE ROW LEVEL SECURITY"));
   assertTrue(sql.contains("input_manifest_sha256 = COALESCE"));
   assertTrue(sql.contains("recon_exception_run_tenant_fk"));
   assertTrue(sql.contains("recon_exception_action_current_tenant_fk"));
   assertTrue(sql.contains("recon_exception_writeoff_approval_check"));
   assertTrue(sql.contains("current_setting('app.tenant_id', true)"));
  }
 }
 @Test void financialRuntimeMigrationVersionsSigningAndFencesJobs() throws Exception {
  try(var input=getClass().getResourceAsStream("/db/migration/V079__financial_runtime.sql")) {
   assertNotNull(input); var sql=new String(input.readAllBytes(),StandardCharsets.UTF_8);
   assertTrue(sql.contains("signing_key_version")); assertTrue(sql.contains("fencing_token"));
   assertTrue(sql.contains("financial_admin_audit")); assertTrue(sql.contains("recon_exception_origin")); assertEquals(3,count(sql,"FORCE ROW LEVEL SECURITY"));
  }
 }
 @Test void postgresUniqueViolationRollsBackToSavepointBeforeReplayQuery() throws Exception {
  var rolledBack=new java.util.concurrent.atomic.AtomicReference<java.sql.Savepoint>();
  var connection=(java.sql.Connection)java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{java.sql.Connection.class},(proxy,method,args)->{if(method.getName().equals("rollback")&&args!=null&&args.length==1){rolledBack.set((java.sql.Savepoint)args[0]); return null;} if(method.getReturnType()==boolean.class)return false; if(method.getReturnType()==int.class)return 0; return null;});
  var savepoint=new java.sql.Savepoint(){public int getSavepointId(){return 1;} public String getSavepointName(){return "before_insert";}};
  TenantSession.rollbackUniqueConflict(connection,savepoint,new java.sql.SQLException("duplicate","23505"));
  assertSame(savepoint,rolledBack.get());
  var other=new java.sql.SQLException("serialization","40001");
  assertSame(other,assertThrows(java.sql.SQLException.class,()->TenantSession.rollbackUniqueConflict(connection,savepoint,other)));
 }
 private static int count(String text,String token) { int result=0,index=0; while((index=text.indexOf(token,index))>=0){result++; index+=token.length();} return result; }
 private static final class TestSigner implements ExportManifestSigner {
  private final byte[] key=new byte[32];
  public Signature sign(byte[] value){return new Signature("test-kms-v1",mac(value));}
  public boolean verify(String version,byte[] value,String signature){return "test-kms-v1".equals(version)&&java.security.MessageDigest.isEqual(mac(value).getBytes(StandardCharsets.US_ASCII),signature.getBytes(StandardCharsets.US_ASCII));}
  public boolean ready(){return true;}
  private String mac(byte[] value){try{var mac=javax.crypto.Mac.getInstance("HmacSHA256");mac.init(new javax.crypto.spec.SecretKeySpec(key,"HmacSHA256"));return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(value));}catch(java.security.GeneralSecurityException failure){throw new IllegalStateException(failure);}}
 }
}
