package com.elmpay.risk.runtime;

import com.elmpay.risk.RiskRequest;
import com.elmpay.risk.SignalSnapshot;

public interface SignalProvider {
    SignalSnapshot fetch(RiskRequest request);
    boolean ready();
}
