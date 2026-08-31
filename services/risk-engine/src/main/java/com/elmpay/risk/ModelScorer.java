package com.elmpay.risk;

import java.math.BigDecimal;

/** Optional model integration. Implementations must return a versioned score. */
@FunctionalInterface
public interface ModelScorer {
    ModelScore score(RiskRequest request, SignalSnapshot signals);

    record ModelScore(boolean available, String version, String contentDigest,
            BigDecimal score, String explanationCode) {
        public ModelScore {
            if (version == null || version.isBlank()) {
                throw new IllegalArgumentException("model version must not be blank");
            }
            if (contentDigest == null || !contentDigest.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("model content digest is invalid");
            }
            score = RiskRule.canonical(score);
            if (score.compareTo(BigDecimal.ZERO) < 0 || score.compareTo(BigDecimal.ONE) > 0) {
                throw new IllegalArgumentException("model score must be between 0 and 1");
            }
            if (explanationCode == null || !explanationCode.matches("[A-Z][A-Z0-9_]{2,63}")) {
                throw new IllegalArgumentException("model explanation must be a stable uppercase code");
            }
        }

        public static ModelScore unavailable(String version, String contentDigest,
                String explanationCode) {
            return new ModelScore(false, version, contentDigest, BigDecimal.ZERO, explanationCode);
        }
    }
}
