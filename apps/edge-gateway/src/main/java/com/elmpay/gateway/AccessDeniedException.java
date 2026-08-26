package com.elmpay.gateway;

/** Authenticated caller lacks the project binding or operation scope. */
final class AccessDeniedException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    AccessDeniedException(String message) {
        super(message);
    }
}
