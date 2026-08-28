package com.elmpay.webhook.ingress;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Resolves an opaque public endpoint token to a server-owned tenant/account binding. */
public final class WebhookIngressRuntime {
    public record EndpointBinding(String tenantId, String projectId, String provider,
            String merchantAccountId) {
        public EndpointBinding {
            requireId(tenantId, "tenantId");
            requireId(projectId, "projectId");
            requireId(provider, "provider");
            requireId(merchantAccountId, "merchantAccountId");
        }
    }

    @FunctionalInterface
    public interface EndpointRegistry {
        Optional<EndpointBinding> resolve(String endpointToken);
    }

    private final EndpointRegistry endpoints;
    private final WebhookIngressService service;

    public WebhookIngressRuntime(EndpointRegistry endpoints, WebhookIngressService service) {
        this.endpoints = Objects.requireNonNull(endpoints, "endpoints");
        this.service = Objects.requireNonNull(service, "service");
    }

    public WebhookIngressService.Receipt ingest(String endpointToken,
            Map<String, String> headers, byte[] rawBody, Instant receivedAt) {
        requireEndpointToken(endpointToken);
        EndpointBinding binding = endpoints.resolve(endpointToken)
                .orElseThrow(() -> new SecurityException("unknown provider webhook endpoint"));
        return service.ingest(new WebhookIngressService.Context(binding.tenantId(),
                binding.projectId(), binding.provider(), binding.merchantAccountId(), receivedAt),
                headers, rawBody);
    }

    static void requireEndpointToken(String value) {
        if (value == null || !value.matches("[A-Za-z0-9_-]{32,256}")) {
            throw new SecurityException("provider webhook endpoint token is invalid");
        }
    }

    private static void requireId(String value, String field) {
        if (value == null || !value.matches("[A-Za-z0-9_-]{2,64}")) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
    }
}
