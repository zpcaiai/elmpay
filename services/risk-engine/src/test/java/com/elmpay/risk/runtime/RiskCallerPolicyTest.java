package com.elmpay.risk.runtime;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class RiskCallerPolicyTest {
    private static final String TENANT = "10000000-0000-0000-0000-000000000001";
    private static final String PROJECT = "20000000-0000-0000-0000-000000000001";

    @Test
    void capabilityIsBoundToExactTenantAndProject() {
        RiskCallerPolicy policy = RiskCallerPolicy.fromBytes(("""
                {"schemaVersion":"1.0","callers":{
                  "spiffe://elmpay.example/edge-gateway":{
                    "capabilities":["risk.evaluate"],
                    "scopes":[{"tenantId":"%s","projectId":"%s"}]
                  }
                }}
                """).formatted(TENANT, PROJECT).getBytes(StandardCharsets.UTF_8));
        assertDoesNotThrow(() -> policy.require("spiffe://elmpay.example/edge-gateway",
                "risk.evaluate", TENANT, PROJECT));
        assertThrows(SecurityException.class, () -> policy.require(
                "spiffe://elmpay.example/edge-gateway", "risk.evaluate", TENANT,
                "20000000-0000-0000-0000-000000000002"));
        assertThrows(SecurityException.class, () -> policy.require(
                "spiffe://elmpay.example/edge-gateway", "operations.approve", TENANT, PROJECT));
    }

    @Test
    void wildcardAndDuplicateScopesAreRejected() {
        assertThrows(IllegalStateException.class, () -> RiskCallerPolicy.fromBytes("""
                {"schemaVersion":"1.0","callers":{"spiffe://elmpay.example/operator":{
                  "capabilities":["operations.approve"],
                  "scopes":[{"tenantId":"*","projectId":"*"}]
                }}}
                """.getBytes(StandardCharsets.UTF_8)));
        assertThrows(IllegalStateException.class, () -> RiskCallerPolicy.fromBytes(("""
                {"schemaVersion":"1.0","callers":{"spiffe://elmpay.example/operator":{
                  "capabilities":["operations.approve"],
                  "scopes":[
                    {"tenantId":"%s","projectId":"%s"},
                    {"tenantId":"%s","projectId":"%s"}
                  ]
                }}}
                """).formatted(TENANT, PROJECT, TENANT, PROJECT)
                .getBytes(StandardCharsets.UTF_8)));
        assertThrows(IllegalStateException.class, () -> RiskCallerPolicy.fromBytes(fullyScoped(
                "spiffe://elmpay.example/risk/../operator")));
        assertThrows(IllegalStateException.class, () -> RiskCallerPolicy.fromBytes(fullyScoped(
                "spiffe://ELMPAY.example/operator")));
        assertThrows(IllegalStateException.class, () -> RiskCallerPolicy.fromBytes(fullyScoped(
                "spiffe://elmpay.example/risk//operator")));
        assertThrows(IllegalStateException.class, () -> RiskCallerPolicy.fromBytes(fullyScoped(
                "spiffe://elmpay.example/operator/")));
        assertThrows(IllegalStateException.class, () -> RiskCallerPolicy.fromBytes(
                new byte[] {'{', (byte) 0xc3, '}'}));
    }

    private static byte[] fullyScoped(String caller) {
        return ("""
                {"schemaVersion":"1.0","callers":{"%s":{
                  "capabilities":["operations.approve"],
                  "scopes":[{"tenantId":"%s","projectId":"%s"}]
                }}}
                """).formatted(caller, TENANT, PROJECT).getBytes(StandardCharsets.UTF_8);
    }
}
