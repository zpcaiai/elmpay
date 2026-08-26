package com.elmpay.payment.checkout;
import static org.junit.jupiter.api.Assertions.*;
import java.time.*; import java.util.*; import org.junit.jupiter.api.Test;
class CapabilityResolverTest {
 @Test void staleHealthFailsClosedAndFallbackIsDeterministic() {
  var now=Instant.parse("2026-08-26T00:00:00Z"); var resolver=new CapabilityResolver();
  var caps=List.of(new CapabilityResolver.Capability("wallet",Set.of("CN"),Set.of("CNY"),Set.of("MOBILE"),true,1),
    new CapabilityResolver.Capability("card",Set.of("CN"),Set.of("CNY"),Set.of("MOBILE"),true,2));
  var health=Map.of("wallet",new CapabilityResolver.Health(true,now.minusSeconds(61)),"card",new CapabilityResolver.Health(true,now));
  var context=new CapabilityResolver.Context("cn","cny","mobile",now,Duration.ofSeconds(60));
  assertEquals("card",resolver.select(caps,health,context));
  assertEquals(List.of("HEALTH_STALE"),resolver.resolve(caps,health,context).stream().filter(d->d.method().equals("wallet")).findFirst().orElseThrow().reasons());
 }
 @Test void localizationUsesVersionedCurrencyPrecisionAndFallbackCatalog() {
  var localization=new CheckoutLocalization("catalog-1",Map.of("en",Map.of("pay","Pay securely"),"ar",Map.of("pay","ادفع بأمان")),Map.of("USD",2,"JPY",0));
  assertEquals("Pay securely",localization.message(Locale.forLanguageTag("en-US"),"pay"));
  assertTrue(localization.formatMoney(1234,"USD",Locale.US).contains("12.34"));
  assertThrows(IllegalArgumentException.class,()->localization.formatMoney(1,"ZZZ",Locale.US));
 }
}
