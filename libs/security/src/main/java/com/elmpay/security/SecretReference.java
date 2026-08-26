package com.elmpay.security;

import java.net.URI;
import java.util.Objects;

/** Reference to externally managed secret material; never the secret value. */
public record SecretReference(URI uri) {
    public SecretReference {
        Objects.requireNonNull(uri, "uri");
        if (!("kms".equals(uri.getScheme()) || "vault".equals(uri.getScheme()))) {
            throw new IllegalArgumentException("secret references must use kms:// or vault://");
        }
        if (uri.getSchemeSpecificPart() == null || uri.getSchemeSpecificPart().isBlank()) {
            throw new IllegalArgumentException("secret reference target is required");
        }
    }

    public static SecretReference parse(String value) {
        return new SecretReference(URI.create(value));
    }
}
