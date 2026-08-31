package com.elmpay.gateway;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Version-controlled provider/version allowlist plus public, server-owned parameters. */
public final class CheckoutProviderSdkRegistry {
    private static final int MAX_MANIFEST_BYTES = 65_536;
    private static final Set<String> DOCUMENT_FIELDS = Set.of("schemaVersion", "manifestVersion",
            "providers");
    private static final Set<String> ENTRY_FIELDS = Set.of("provider", "methods", "sdkVersion",
            "enabled", "publicParameters");
    private static final String RESOURCE = "provider-sdk-runtime.json";

    public record Configuration(String method, String provider, String sdkVersion,
            Map<String, String> publicParameters, String policyVersion) {
        public Configuration {
            publicParameters = Map.copyOf(publicParameters);
        }
    }

    private final String policyVersion;
    private final Map<String, Entry> byProviderAndMethod;
    private final Map<String, String> environment;

    CheckoutProviderSdkRegistry(String policyVersion, List<Entry> entries,
            Map<String, String> environment) {
        this.policyVersion = requiredIdentifier(policyVersion, "provider SDK manifest version");
        this.environment = Map.copyOf(Objects.requireNonNull(environment, "environment"));
        Map<String, Entry> index = new LinkedHashMap<>();
        for (Entry entry : entries) {
            for (String method : entry.methods()) {
                if (index.putIfAbsent(entry.provider() + "\u001f" + method, entry) != null) {
                    throw new IllegalArgumentException(
                            "provider SDK manifest contains a duplicate provider/method");
                }
            }
        }
        this.byProviderAndMethod = Map.copyOf(index);
    }

    public static CheckoutProviderSdkRegistry fromClasspath(Map<String, String> environment) {
        try (InputStream input = CheckoutProviderSdkRegistry.class.getClassLoader()
                .getResourceAsStream(RESOURCE)) {
            if (input == null) {
                throw new IllegalStateException("provider SDK runtime allowlist is missing");
            }
            byte[] bytes = input.readNBytes(MAX_MANIFEST_BYTES + 1);
            if (bytes.length > MAX_MANIFEST_BYTES) {
                throw new IllegalStateException("provider SDK runtime allowlist is too large");
            }
            Map<String, Object> document = Json.object(new String(bytes, StandardCharsets.UTF_8));
            if (!DOCUMENT_FIELDS.equals(document.keySet())
                    || !Long.valueOf(1L).equals(document.get("schemaVersion"))
                    || !(document.get("providers") instanceof List<?> rawEntries)) {
                throw new IllegalArgumentException("provider SDK runtime allowlist is invalid");
            }
            List<Entry> entries = rawEntries.stream().map(CheckoutProviderSdkRegistry::entry).toList();
            return new CheckoutProviderSdkRegistry(text(document.get("manifestVersion")), entries,
                    environment);
        } catch (IOException failure) {
            throw new IllegalStateException("provider SDK runtime allowlist cannot be read", failure);
        }
    }

    public Optional<Configuration> resolve(String provider, String method) {
        Entry entry = byProviderAndMethod.get(provider + "\u001f" + method);
        if (entry == null || !entry.enabled()) {
            return Optional.empty();
        }
        Map<String, String> values = new LinkedHashMap<>();
        entry.publicParameters().forEach((name, environmentName) -> {
            String value = environment.get(environmentName);
            if (value == null || value.isBlank() || value.length() > 512
                    || !value.matches("[\\x20-\\x7e]+") || value.matches(".*[<>].*")) {
                throw new IllegalStateException(
                        "provider SDK public parameter is missing or invalid: " + name);
            }
            values.put(name, value);
        });
        return Optional.of(new Configuration(method, provider, entry.sdkVersion(), values,
                policyVersion));
    }

    private static Entry entry(Object value) {
        if (!(value instanceof Map<?, ?> raw)) {
            throw new IllegalArgumentException("provider SDK allowlist entry is invalid");
        }
        Map<String, Object> object = new LinkedHashMap<>();
        raw.forEach((key, item) -> object.put(String.valueOf(key), item));
        if (!ENTRY_FIELDS.equals(object.keySet()) || !(object.get("enabled") instanceof Boolean enabled)
                || !(object.get("methods") instanceof List<?> rawMethods)
                || rawMethods.isEmpty() || !(object.get("publicParameters") instanceof Map<?, ?> rawParameters)) {
            throw new IllegalArgumentException("provider SDK allowlist entry is invalid");
        }
        String provider = normalized(text(object.get("provider")), "provider");
        String version = requiredIdentifier(text(object.get("sdkVersion")), "SDK version");
        Set<String> methods = rawMethods.stream().map(item -> normalized(text(item), "method"))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        if (methods.size() != rawMethods.size()) {
            throw new IllegalArgumentException("provider SDK methods contain duplicates");
        }
        Map<String, String> parameters = new LinkedHashMap<>();
        rawParameters.forEach((key, item) -> {
            String name = text(key);
            String environmentName = text(item);
            if (!name.matches("[A-Za-z][A-Za-z0-9._-]{0,63}")
                    || name.matches("(?i).*(secret|private|password|credential|token|pan|cvv|cvc).*" )
                    || !environmentName.matches("ELMPAY_PROVIDER_PUBLIC_[A-Z0-9_]{1,96}")) {
                throw new IllegalArgumentException("provider SDK public parameter binding is invalid");
            }
            if (parameters.putIfAbsent(name, environmentName) != null) {
                throw new IllegalArgumentException("provider SDK public parameter is duplicated");
            }
        });
        return new Entry(provider, methods, version, enabled, Map.copyOf(parameters));
    }

    private static String text(Object value) {
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException("provider SDK manifest text is required");
        }
        return text;
    }

    private static String normalized(String value, String field) {
        if (!value.matches("[a-z0-9][a-z0-9._-]{0,63}")) {
            throw new IllegalArgumentException("provider SDK " + field + " is invalid");
        }
        return value;
    }

    private static String requiredIdentifier(String value, String field) {
        if (!value.matches("[A-Za-z0-9._:-]{1,128}")) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return value;
    }

    record Entry(String provider, Set<String> methods, String sdkVersion, boolean enabled,
            Map<String, String> publicParameters) {
    }
}
