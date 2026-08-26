package com.elmpay.merchant;

public enum AccountStatus {
    PENDING,
    ACTIVE,
    SUSPENDED,
    REVOKED;

    public boolean permitsNewPayments() {
        return this == ACTIVE;
    }

    public boolean permitsRefunds() {
        return this == ACTIVE || this == SUSPENDED;
    }
}
