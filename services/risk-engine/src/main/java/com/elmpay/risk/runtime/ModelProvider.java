package com.elmpay.risk.runtime;

import com.elmpay.risk.ModelScorer;
import com.elmpay.risk.RiskRequest;
import com.elmpay.risk.SignalSnapshot;

public interface ModelProvider {
    ModelScorer.ModelScore score(RiskRequest request, SignalSnapshot signals);
    boolean ready();
}
