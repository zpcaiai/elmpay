package com.elmpay.risk.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.elmpay.risk.RiskAction;
import com.elmpay.risk.RiskDecision;
import com.elmpay.risk.RiskGateException;
import com.elmpay.risk.RiskOperation;
import com.elmpay.risk.SynchronousRiskGate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class RiskProtectedIdentityServiceTest {
    private static final Instant NOW = Instant.parse("2026-08-28T00:00:00Z");
    private static final IdentityMutationCommand COMMAND = new IdentityMutationCommand(
            "tenant-a", "identity-request-1", "account-1", Map.of("deviceDigest", "a".repeat(64)));

    @Test
    void allIdentityMutationsAreSynchronouslyGatedAndCredentialChangeRevokesSessions() {
        RecordingPort port = new RecordingPort();
        java.util.ArrayList<RiskOperation> operations = new java.util.ArrayList<>();
        RiskProtectedIdentityService service = service(port, request -> {
            operations.add(request.operation());
            return decision(request.tenantId(), request.requestId(), RiskAction.APPROVE);
        });

        service.changeCredential(COMMAND);
        service.addPaymentMethod(COMMAND);
        service.elevatePrivilege(COMMAND);

        assertEquals(List.of(RiskOperation.CREDENTIAL_CHANGE, RiskOperation.PAYMENT_METHOD_ADD,
                RiskOperation.PRIVILEGE_ELEVATION), operations);
        assertEquals(1, port.credentialChanges.get());
        assertEquals(1, port.paymentMethods.get());
        assertEquals(1, port.privilegeChanges.get());
    }

    @Test
    void reviewBlockTimeoutAndBindingMismatchNeverReachIdentityMutationPort() {
        for (SynchronousRiskGate gate : List.<SynchronousRiskGate>of(
                request -> decision(request.tenantId(), request.requestId(), RiskAction.REVIEW),
                request -> decision(request.tenantId(), request.requestId(), RiskAction.BLOCK),
                request -> { throw new IllegalStateException("timeout"); },
                request -> decision("other-tenant", request.requestId(), RiskAction.APPROVE))) {
            RecordingPort port = new RecordingPort();
            RiskProtectedIdentityService service = service(port, gate);

            assertThrows(RiskGateException.class, () -> service.changeCredential(COMMAND));
            assertThrows(RiskGateException.class, () -> service.addPaymentMethod(COMMAND));
            assertThrows(RiskGateException.class, () -> service.elevatePrivilege(COMMAND));
            assertEquals(0, port.total());
        }
    }

    private static RiskProtectedIdentityService service(IdentityMutationPort port,
            SynchronousRiskGate gate) {
        return new RiskProtectedIdentityService(port, gate,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static RiskDecision decision(String tenantId, String requestId, RiskAction action) {
        return new RiskDecision("decision-1", tenantId, requestId, action,
                List.of("TEST_DECISION"), "rules-1", "a".repeat(64), "signals-1", "model-1",
                action != RiskAction.APPROVE, NOW);
    }

    private static final class RecordingPort implements IdentityMutationPort {
        private final AtomicInteger credentialChanges = new AtomicInteger();
        private final AtomicInteger paymentMethods = new AtomicInteger();
        private final AtomicInteger privilegeChanges = new AtomicInteger();

        @Override
        public void changeCredentialAndRevokeSessions(IdentityMutationCommand command) {
            credentialChanges.incrementAndGet();
        }

        @Override
        public void addPaymentMethod(IdentityMutationCommand command) {
            paymentMethods.incrementAndGet();
        }

        @Override
        public void elevatePrivilege(IdentityMutationCommand command) {
            privilegeChanges.incrementAndGet();
        }

        private int total() {
            return credentialChanges.get() + paymentMethods.get() + privilegeChanges.get();
        }
    }
}
