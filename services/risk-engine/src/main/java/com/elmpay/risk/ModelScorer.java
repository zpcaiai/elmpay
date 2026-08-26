package com.elmpay.risk;

/** Optional model integration. Implementations must return a versioned score. */
@FunctionalInterface
public interface ModelScorer {
    ModelScore score(RiskRequest request, SignalSnapshot signals);

    record ModelScore(boolean available, String version, double score, String explanationCode) {
        public ModelScore {
            if (version == null || version.isBlank()) {
                throw new IllegalArgumentException("model version must not be blank");
            }
            if (!Double.isFinite(score) || score < 0.0 || score > 1.0) {
                throw new IllegalArgumentException("model score must be between 0 and 1");
            }
            if (explanationCode == null || !explanationCode.matches("[A-Z][A-Z0-9_]{2,63}")) {
                throw new IllegalArgumentException("model explanation must be a stable uppercase code");
            }
        }

        public static ModelScore unavailable(String version, String explanationCode) {
            return new ModelScore(false, version, 0.0, explanationCode);
        }
    }
}
