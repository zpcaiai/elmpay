package com.elmpay.ledger;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets; import java.time.*; import java.util.*; import org.junit.jupiter.api.Test;
class LedgerRulesTest {
 @Test void postingMustBalancePerCurrency() {
  assertDoesNotThrow(()->LedgerService.validateBalanced(List.of(new LedgerService.EntryDraft("cash",LedgerService.Direction.DEBIT,100,"USD"),new LedgerService.EntryDraft("merchant",LedgerService.Direction.CREDIT,100,"USD"))));
  assertThrows(IllegalArgumentException.class,()->LedgerService.validateBalanced(List.of(new LedgerService.EntryDraft("cash",LedgerService.Direction.DEBIT,100,"USD"),new LedgerService.EntryDraft("merchant",LedgerService.Direction.CREDIT,99,"USD"))));
  assertThrows(IllegalArgumentException.class,()->LedgerService.validateBalanced(List.of(new LedgerService.EntryDraft("cash",LedgerService.Direction.DEBIT,100,"USD"),new LedgerService.EntryDraft("merchant",LedgerService.Direction.CREDIT,100,"EUR"))));
 }
 @Test void feesAndFxAreExact() {
  var service=new FeeFxSettlementService(); var fee=service.quote(10_000,"USD",new FeeFxSettlementService.FeeRule(30,29,1000,1,10,FeeFxSettlementService.Rounding.HALF_EVEN,"v1"));
  assertEquals(290,fee.variableMinor()); assertEquals(32,fee.taxMinor()); assertEquals(352,fee.totalFeeMinor());
 var fx=service.convert(101,new FeeFxSettlementService.FxRate("source","USD","JPY",3,2,Instant.EPOCH,"r1"),FeeFxSettlementService.Rounding.HALF_EVEN);
  assertEquals(152,fx.targetMinor());
 }
 @Test void migrationUsesCanonicalSchemaAndEnforcesSingleReversalAndRls() throws Exception {
  try(var input=getClass().getResourceAsStream("/db/migration/V001__immutable_ledger.sql")) {
   assertNotNull(input); var sql=new String(input.readAllBytes(),StandardCharsets.UTF_8);
   assertTrue(sql.contains("source_kind text")); assertTrue(sql.contains("posted_at timestamptz"));
   assertTrue(sql.contains("ledger_transaction_single_reversal_unique"));
   assertTrue(sql.contains("WHERE reversal_of IS NOT NULL"));
   assertTrue(sql.contains("request_hash = 'legacy:'"));
   assertTrue(sql.contains("ALTER COLUMN request_hash SET NOT NULL"));
   assertTrue(sql.contains("ledger_transaction_adjustment_approval_check"));
   assertEquals(6,count(sql,"FORCE ROW LEVEL SECURITY"));
   assertTrue(sql.contains("current_setting('app.tenant_id', true)"));
  }
 }
 @Test void reversalApprovalIsFailClosed() {
  var source=(javax.sql.DataSource)java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{javax.sql.DataSource.class},(proxy,method,args)->{throw new AssertionError("database must not be reached");});
  var ledger=new LedgerService(source,Clock.systemUTC());
  assertThrows(IllegalArgumentException.class,()->ledger.reverse(UUID.randomUUID().toString(),UUID.randomUUID().toString(),"reversal-1","reason",Instant.EPOCH));
 }
 @Test void postgresUniqueViolationRollsBackToSavepointBeforeReplayQuery() throws Exception {
  var rolledBack=new java.util.concurrent.atomic.AtomicReference<java.sql.Savepoint>();
  var connection=(java.sql.Connection)java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{java.sql.Connection.class},(proxy,method,args)->{if(method.getName().equals("rollback")&&args!=null&&args.length==1){rolledBack.set((java.sql.Savepoint)args[0]); return null;} if(method.getReturnType()==boolean.class)return false; if(method.getReturnType()==int.class)return 0; return null;});
  var savepoint=new java.sql.Savepoint(){public int getSavepointId(){return 1;} public String getSavepointName(){return "before_insert";}};
  LedgerService.rollbackUniqueConflict(connection,savepoint,new java.sql.SQLException("duplicate","23505"));
  assertSame(savepoint,rolledBack.get());
  var other=new java.sql.SQLException("serialization","40001");
  assertSame(other,assertThrows(java.sql.SQLException.class,()->LedgerService.rollbackUniqueConflict(connection,savepoint,other)));
 }
 private static int count(String text,String token) { int result=0,index=0; while((index=text.indexOf(token,index))>=0){result++; index+=token.length();} return result; }
}
