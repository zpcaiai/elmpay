package com.elmpay.payment.checkout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class CheckoutLocalizationCatalogTest {
    @Test
    void defaultCatalogProvidesVersionedFallbackRtlA11yAndExactCurrencyScale() {
        CheckoutLocalization catalog = CheckoutLocalization.defaultCatalog();

        assertEquals("checkout-catalog-2026-08-v1", catalog.catalogVersion());
        assertEquals("zh-CN", catalog.localeTag(Locale.forLanguageTag("zh-CN")));
        assertEquals("银行卡", catalog.methodLabel(Locale.forLanguageTag("zh-CN"), "card"));
        assertEquals("rtl", catalog.direction(Locale.forLanguageTag("ar-SA")));
        assertEquals("en", catalog.localeTag(Locale.forLanguageTag("fr-FR")));
        assertTrue(catalog.browserMessages(Locale.forLanguageTag("ar"), "OPEN")
                .keySet().containsAll(java.util.Set.of("ui.pageTitle", "ui.methodLegend",
                        "ui.continueAction", "status.current", "error.notVerified")));
        String jpy = catalog.formatMoney(1_234, "JPY", Locale.JAPAN);
        assertTrue(jpy.contains("1,234"));
        assertThrows(IllegalArgumentException.class, () -> catalog.formatMoney(1, "ZZZ",
                Locale.US));
    }

    @Test
    void incompleteLocaleCatalogIsRejectedInsteadOfSilentlyDroppingMessages() {
        assertThrows(IllegalArgumentException.class, () -> new CheckoutLocalization("v1",
                Map.of("en", Map.of("pay", "Pay", "cancel", "Cancel"),
                        "ar", Map.of("pay", "ادفع")), Map.of("USD", 2)));
    }
}
