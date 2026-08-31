package com.elmpay.risk.runtime;

import com.elmpay.events.StrictJson;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Deployment-governed SPIFFE allowlist; request bodies cannot self-assert capabilities. */
public final class RiskCallerPolicy {
    private static final Set<String> CAPABILITIES = Set.of("risk.evaluate", "rules.propose",
            "rules.approve", "rules.activate", "operations.propose", "operations.approve");
    private final Map<String, Grant> callers;

    private RiskCallerPolicy(Map<String, Grant> callers) {
        this.callers = Map.copyOf(callers);
    }

    static RiskCallerPolicy fromBytes(byte[] raw) {
        Map<String, Object> document = StrictJson.object(strictUtf8(raw));
        if (!Set.of("schemaVersion", "callers").equals(document.keySet())
                || !"1.0".equals(document.get("schemaVersion"))
                || !(document.get("callers") instanceof Map<?, ?> configured)
                || configured.isEmpty() || configured.size() > 128) {
            throw new IllegalStateException("risk caller policy schema is invalid");
        }
        Map<String, Grant> parsed = new HashMap<>();
        configured.forEach((rawCaller, rawGrant) -> {
            if (!(rawCaller instanceof String caller)
                    || !canonicalSpiffe(caller)
                    || !(rawGrant instanceof Map<?, ?> grant)
                    || !grant.keySet().equals(Set.of("capabilities", "scopes"))
                    || !(grant.get("capabilities") instanceof List<?> values)
                    || values.isEmpty() || values.size() > CAPABILITIES.size()
                    || !(grant.get("scopes") instanceof List<?> rawScopes)
                    || rawScopes.isEmpty() || rawScopes.size() > 1024) {
                throw new IllegalStateException("risk caller policy entry is invalid");
            }
            Set<String> capabilities = new HashSet<>();
            for (Object rawCapability : values) {
                if (!(rawCapability instanceof String capability)
                        || !CAPABILITIES.contains(capability) || !capabilities.add(capability)) {
                    throw new IllegalStateException("risk caller capability is invalid");
                }
            }
            Set<Scope> scopes = new HashSet<>();
            for (Object rawScope : rawScopes) {
                if (!(rawScope instanceof Map<?, ?> scope)
                        || !scope.keySet().equals(Set.of("tenantId", "projectId"))
                        || !(scope.get("tenantId") instanceof String tenantId)
                        || !(scope.get("projectId") instanceof String projectId)
                        || !scopes.add(new Scope(configuredUuid(tenantId),
                                configuredUuid(projectId)))) {
                    throw new IllegalStateException("risk caller scope is invalid");
                }
            }
            parsed.put(caller, new Grant(Set.copyOf(capabilities), Set.copyOf(scopes)));
        });
        return new RiskCallerPolicy(parsed);
    }

    public void require(String caller, String capability, String tenantId, String projectId) {
        Grant grant = callers.get(caller);
        Scope scope = new Scope(canonicalUuid(tenantId), canonicalUuid(projectId));
        if (grant == null || !grant.capabilities().contains(capability)
                || !grant.scopes().contains(scope)) {
            throw new SecurityException("risk caller is not authorized for this capability");
        }
    }

    private static String configuredUuid(String value) {
        try {
            return canonicalUuid(value);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalStateException("risk caller scope UUID is invalid", invalid);
        }
    }

    private static String canonicalUuid(String value) {
        try {
            UUID parsed = UUID.fromString(value);
            if (!parsed.toString().equals(value)) throw new IllegalArgumentException();
            return value;
        } catch (RuntimeException invalid) {
            throw new IllegalArgumentException("risk tenant/project UUID is invalid", invalid);
        }
    }

    static boolean canonicalSpiffe(String value) {
        try {
            URI uri = URI.create(value);
            return "spiffe".equals(uri.getScheme()) && uri.getHost() != null
                    && uri.getPort() == -1 && uri.getUserInfo() == null
                    && uri.getQuery() == null && uri.getFragment() == null
                    && uri.getRawPath() != null && uri.getRawPath().equals(uri.getPath())
                    && uri.normalize().equals(uri)
                    && uri.getPath().matches(
                            "/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")
                    && value.equals("spiffe://"
                            + uri.getHost().toLowerCase(java.util.Locale.ROOT)
                            + uri.getPath());
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private static String strictUtf8(byte[] value) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(value)).toString();
        } catch (java.nio.charset.CharacterCodingException invalid) {
            throw new IllegalStateException("risk caller policy is not canonical UTF-8", invalid);
        }
    }

    private record Scope(String tenantId, String projectId) { }
    private record Grant(Set<String> capabilities, Set<Scope> scopes) { }
}
