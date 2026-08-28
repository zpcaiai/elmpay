package com.elmpay.risk.identity;

import com.elmpay.risk.RiskEvaluationRequest;
import com.elmpay.risk.RiskGateEnforcer;
import com.elmpay.risk.RiskOperation;
import com.elmpay.risk.SynchronousRiskGate;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Product decorator for high-impact identity changes. REVIEW/BLOCK/unavailable decisions stop the
 * underlying mutation; credential changes atomically revoke existing sessions through the port.
 */
public final class RiskProtectedIdentityService {
    private final IdentityMutationPort mutations;
    private final SynchronousRiskGate riskGate;
    private final Clock clock;

    public RiskProtectedIdentityService(IdentityMutationPort mutations,
            SynchronousRiskGate riskGate, Clock clock) {
        this.mutations = Objects.requireNonNull(mutations, "mutations");
        this.riskGate = Objects.requireNonNull(riskGate, "riskGate");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public void changeCredential(IdentityMutationCommand command) {
        requireApproved(command, RiskOperation.CREDENTIAL_CHANGE);
        mutations.changeCredentialAndRevokeSessions(command);
    }

    public void addPaymentMethod(IdentityMutationCommand command) {
        requireApproved(command, RiskOperation.PAYMENT_METHOD_ADD);
        mutations.addPaymentMethod(command);
    }

    public void elevatePrivilege(IdentityMutationCommand command) {
        requireApproved(command, RiskOperation.PRIVILEGE_ELEVATION);
        mutations.elevatePrivilege(command);
    }

    private void requireApproved(IdentityMutationCommand command, RiskOperation operation) {
        Objects.requireNonNull(command, "command");
        Map<String, String> attributes = new LinkedHashMap<>(command.attributes());
        attributes.put("identityOperation", operation.name());
        RiskGateEnforcer.requireApproved(riskGate, new RiskEvaluationRequest(
                command.tenantId(), operation.name() + ":" + command.requestId(), operation,
                command.subjectId(), 0, "XXX", clock.instant(), attributes));
    }
}
