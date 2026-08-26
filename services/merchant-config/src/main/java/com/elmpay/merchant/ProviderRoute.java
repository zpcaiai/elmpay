package com.elmpay.merchant;

import java.util.Objects;

public record ProviderRoute(ProviderAccount account, ProviderCapability capability,
        int priority, String ruleVersion) {
    public ProviderRoute {
        Objects.requireNonNull(account, "account");
        Objects.requireNonNull(capability, "capability");
        Objects.requireNonNull(ruleVersion, "ruleVersion");
        if (!account.provider().equals(capability.provider()) || priority < 0
                || ruleVersion.isBlank()) {
            throw new IllegalArgumentException("invalid provider route");
        }
    }
}
