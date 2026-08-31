package com.elmpay.risk.runtime;

import com.elmpay.risk.RiskDecision;
import com.elmpay.risk.RiskEvaluationRequest;
import java.time.Instant;

public interface RiskDecisionService {
    record NonceBinding(String tenantId, String projectId, String requestId,
            String requestDigest) { }
    record NonceChallenge(String nonce, Instant expiresAt) { }

    NonceChallenge issueNonce(NonceBinding binding, String callerSpiffeId);
    RiskDecision decide(RiskEvaluationRequest request, String nonce, String callerSpiffeId);
    boolean ready();
}
