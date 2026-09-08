package com.elmpay.payment.checkout;

import com.elmpay.idempotency.RequestFingerprint;
import com.elmpay.money.Money;
import com.elmpay.payment.ConfirmationCommand;
import com.elmpay.payment.ConfirmationMode;
import com.elmpay.payment.CreateIntentCommand;
import com.elmpay.payment.PaymentIntent;
import com.elmpay.payment.PaymentMethodReference;
import com.elmpay.payment.PaymentCoreException;
import com.elmpay.payment.PaymentService;
import com.elmpay.security.CanonicalPayload;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Hosted-checkout application service. Checkout state is only a presentation
 * projection: a successful view is derived exclusively from the authoritative
 * {@link PaymentService} intent state.
 */
public final class HostedCheckoutService {
    private static final String DEFAULT_DEVICE_CONTEXT = "device-context-not-provided";

    public record CreateCommand(UUID tenantId, UUID projectId, UUID merchantId,
            String businessOrderNo, long amountMinor, String currency, String returnRouteId,
            String deviceContextDigest, String idempotencyKey, String paymentMethod) {
        public CreateCommand {
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(projectId, "projectId");
            Objects.requireNonNull(merchantId, "merchantId");
            requireText(businessOrderNo, "businessOrderNo", 128);
            if (amountMinor <= 0) {
                throw new IllegalArgumentException("amount must be a positive integer minor-unit value");
            }
            Money.of(amountMinor, currency);
            if (returnRouteId != null && !returnRouteId.matches("[a-z0-9][a-z0-9._-]{0,63}")) {
                throw new IllegalArgumentException("return_route_id is invalid");
            }
            deviceContextDigest = normalizeDeviceContext(deviceContextDigest);
            RequestFingerprint.validateKey(idempotencyKey);
            paymentMethod = paymentMethod == null ? null : normalizeMethod(paymentMethod);
        }

        /** Backwards-compatible command for callers that intentionally expose all configured methods. */
        public CreateCommand(UUID tenantId, UUID projectId, UUID merchantId,
                String businessOrderNo, long amountMinor, String currency, String returnRouteId,
                String deviceContextDigest, String idempotencyKey) {
            this(tenantId, projectId, merchantId, businessOrderNo, amountMinor, currency,
                    returnRouteId, deviceContextDigest, idempotencyKey, null);
        }
    }

    public record Created(String checkoutSessionId, String paymentIntentId, Instant expiresAt,
            URI checkoutUrl, String status) {
    }

    public record MethodView(String id, String label, boolean eligible, String reason) {
    }

    public record View(String checkoutSessionId, String paymentIntentId, String businessOrderNo,
            long amount, String currency, String returnRouteId, Instant expiresAt, String status,
            String displayAmount, String locale, String direction, List<MethodView> methods,
            Map<String, String> nextAction, String catalogVersion,
            Map<String, String> messages) {
        public View {
            methods = List.copyOf(methods);
            nextAction = Map.copyOf(nextAction);
            messages = Map.copyOf(messages);
        }
    }

    public record ConfirmCommand(String method, String paymentMethodReference, String fingerprint,
            Map<String, String> providerParameters, String idempotencyKey, String correlationId) {
        public ConfirmCommand {
            requireText(method, "payment method", 64);
            if (!method.matches("[A-Za-z0-9._-]+")) {
                throw new IllegalArgumentException("payment method is invalid");
            }
            if (paymentMethodReference != null && paymentMethodReference.length() > 512) {
                throw new IllegalArgumentException("payment method reference is too long");
            }
            if (fingerprint != null && fingerprint.length() > 128) {
                throw new IllegalArgumentException("payment method fingerprint is too long");
            }
            providerParameters = providerParameters == null ? Map.of()
                    : Map.copyOf(providerParameters);
            RequestFingerprint.validateKey(idempotencyKey);
            requireText(correlationId, "correlationId", 128);
        }
    }

    /** Immutable, revalidated authorization returned before a browser provider SDK is exposed. */
    public record ProviderSdkAuthorization(String checkoutSessionId, UUID tenantId, UUID projectId,
            UUID merchantId, UUID paymentIntentId, String method, UUID providerAccountId,
            String provider, String capabilityVersion, String businessOrderDigest,
            String checkoutSnapshotDigest, Instant expiresAt) {
    }

    private final PaymentService payments;
    private final CheckoutSessionRepository repository;
    private final CheckoutTokenSigner signer;
    private final Map<String, URI> returnRoutes;
    private final String defaultReturnRouteId;
    private final Set<String> allowedMethods;
    private final URI publicBaseUri;
    private final Duration sessionTtl;
    private final String region;
    private final boolean allowSyntheticPaymentReference;
    private final Clock clock;
    private final CheckoutLocalization localization;
    private final CheckoutCapabilitySource capabilitySource;
    private final CheckoutProviderSdkSource providerSdkSource;

    public HostedCheckoutService(PaymentService payments, CheckoutSessionRepository repository,
            CheckoutTokenSigner signer,
            Map<String, URI> returnRoutes, String defaultReturnRouteId,
            Set<String> allowedMethods, URI publicBaseUri, Duration sessionTtl, String region,
            boolean allowSyntheticPaymentReference, Clock clock) {
        this(payments, repository, signer, returnRoutes, defaultReturnRouteId, allowedMethods,
                publicBaseUri, sessionTtl, region, allowSyntheticPaymentReference, clock,
                new ConfiguredCheckoutCapabilitySource(allowedMethods),
                CheckoutLocalization.defaultCatalog(), CheckoutProviderSdkSource.disabled());
    }

    public HostedCheckoutService(PaymentService payments, CheckoutSessionRepository repository,
            CheckoutTokenSigner signer, Map<String, URI> returnRoutes,
            String defaultReturnRouteId, Set<String> allowedMethods, URI publicBaseUri,
            Duration sessionTtl, String region, boolean allowSyntheticPaymentReference,
            Clock clock, CheckoutCapabilitySource capabilitySource,
            CheckoutLocalization localization) {
        this(payments, repository, signer, returnRoutes, defaultReturnRouteId, allowedMethods,
                publicBaseUri, sessionTtl, region, allowSyntheticPaymentReference, clock,
                capabilitySource, localization, CheckoutProviderSdkSource.disabled());
    }

    public HostedCheckoutService(PaymentService payments, CheckoutSessionRepository repository,
            CheckoutTokenSigner signer, Map<String, URI> returnRoutes,
            String defaultReturnRouteId, Set<String> allowedMethods, URI publicBaseUri,
            Duration sessionTtl, String region, boolean allowSyntheticPaymentReference,
            Clock clock, CheckoutCapabilitySource capabilitySource,
            CheckoutLocalization localization, CheckoutProviderSdkSource providerSdkSource) {
        this.payments = Objects.requireNonNull(payments, "payments");
        this.repository = Objects.requireNonNull(repository, "repository");
        this.signer = Objects.requireNonNull(signer, "signer");
        this.returnRoutes = Map.copyOf(Objects.requireNonNull(returnRoutes, "returnRoutes"));
        this.returnRoutes.forEach((routeId, returnUri) -> {
            if (!routeId.matches("[a-z0-9][a-z0-9._-]{0,63}")
                    || returnUri == null || !returnUri.isAbsolute()
                    || !"https".equalsIgnoreCase(returnUri.getScheme())
                    || returnUri.getHost() == null || returnUri.getUserInfo() != null
                    || returnUri.getFragment() != null) {
                throw new IllegalArgumentException("checkout return route configuration is invalid");
            }
        });
        if (this.returnRoutes.isEmpty() || !this.returnRoutes.containsKey(defaultReturnRouteId)) {
            throw new IllegalArgumentException("default return route must be registered");
        }
        this.defaultReturnRouteId = defaultReturnRouteId;
        if (allowedMethods == null || allowedMethods.isEmpty()) {
            throw new IllegalArgumentException("at least one checkout payment method is required");
        }
        this.allowedMethods = allowedMethods.stream().map(HostedCheckoutService::normalizeMethod)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        this.publicBaseUri = validatePublicBase(publicBaseUri);
        this.sessionTtl = Objects.requireNonNull(sessionTtl, "sessionTtl");
        if (sessionTtl.compareTo(Duration.ofMinutes(1)) < 0
                || sessionTtl.compareTo(Duration.ofMinutes(30)) > 0) {
            throw new IllegalArgumentException("checkout session TTL must be 1-30 minutes");
        }
        if (region == null || !region.matches("[A-Za-z]{2}")) {
            throw new IllegalArgumentException("checkout region must be ISO alpha-2");
        }
        this.region = region.toUpperCase(Locale.ROOT);
        this.allowSyntheticPaymentReference = allowSyntheticPaymentReference;
        this.clock = Objects.requireNonNull(clock, "clock");
        this.capabilitySource = Objects.requireNonNull(capabilitySource, "capabilitySource");
        this.localization = Objects.requireNonNull(localization, "localization");
        this.providerSdkSource = Objects.requireNonNull(providerSdkSource, "providerSdkSource");
    }

    /** Creates one immutable payment intent and one signed session per request key. */
    public Created create(CreateCommand command) {
        Objects.requireNonNull(command, "command");
        String routeId = command.returnRouteId() == null ? defaultReturnRouteId
                : command.returnRouteId();
        URI returnUri = returnRoutes.get(routeId);
        if (returnUri == null) {
            throw new IllegalArgumentException("return route is not registered");
        }
        Set<String> requestedMethods = command.paymentMethod() == null
                ? allowedMethods : Set.of(command.paymentMethod());
        if (!allowedMethods.containsAll(requestedMethods)) {
            throw new IllegalArgumentException("payment method is not enabled for checkout");
        }
        Map<String, Object> fingerprint = new java.util.LinkedHashMap<>();
        fingerprint.put("tenant_id", command.tenantId().toString());
        fingerprint.put("project_id", command.projectId().toString());
        fingerprint.put("merchant_id", command.merchantId().toString());
        fingerprint.put("business_order_no", command.businessOrderNo());
        fingerprint.put("amount", command.amountMinor());
        fingerprint.put("currency", command.currency().toUpperCase(Locale.ROOT));
        fingerprint.put("return_route_id", routeId);
        fingerprint.put("device_context_digest", command.deviceContextDigest());
        if (command.paymentMethod() != null) {
            fingerprint.put("payment_method", command.paymentMethod());
        }
        String digest = CanonicalPayload.sha256Hex(fingerprint);
        CheckoutSessionRepository.Record replay = repository.findByCreateKey(command.tenantId(),
                command.projectId(), command.idempotencyKey()).orElse(null);
        if (replay != null) {
            requireSameRequest(replay, digest);
            return created(replay);
        }
        PaymentIntent intent = payments.create(new CreateIntentCommand(command.tenantId(),
                command.projectId(), command.merchantId(), command.businessOrderNo(),
                Money.of(command.amountMinor(), command.currency()), requestedMethods,
                ConfirmationMode.AUTOMATIC, region, sessionTtl, command.idempotencyKey()));
        Instant now = clock.instant();
        CheckoutSessionRepository.Record candidate = new CheckoutSessionRepository.Record(
                UUID.randomUUID().toString(), command.tenantId(), command.projectId(),
                command.merchantId(), intent.id(), command.businessOrderNo(), command.amountMinor(),
                command.currency().toUpperCase(Locale.ROOT), routeId, returnUri,
                command.deviceContextDigest(), now.plus(sessionTtl), signer.activeKeyId(),
                signer.newNonce(), requestedMethods, command.idempotencyKey(), digest, now);
        CheckoutSessionRepository.Record winner = repository.createOrGet(candidate);
        requireSameRequest(winner, digest);
        return created(winner);
    }

    public View getForPrincipal(UUID tenantId, UUID projectId, String sessionId) {
        return getForPrincipal(tenantId, projectId, sessionId, Locale.ENGLISH, "WEB");
    }

    public View getForPrincipal(UUID tenantId, UUID projectId, String sessionId, Locale locale,
            String deviceClass) {
        CheckoutSessionRepository.Record session = requirePrincipalSession(tenantId, projectId,
                sessionId);
        return view(session, locale, deviceClass);
    }

    public View getForBrowser(String sessionId, String accessToken) {
        return getForBrowser(sessionId, accessToken, Locale.ENGLISH, "WEB");
    }

    public View getForBrowser(String sessionId, String accessToken, Locale locale,
            String deviceClass) {
        return view(requireBrowserSession(sessionId, accessToken), locale, deviceClass);
    }

    public View confirmForPrincipal(UUID tenantId, UUID projectId, String sessionId,
            ConfirmCommand command) {
        return confirmForPrincipal(tenantId, projectId, sessionId, command, Locale.ENGLISH,
                "WEB");
    }

    public View confirmForPrincipal(UUID tenantId, UUID projectId, String sessionId,
            ConfirmCommand command, Locale locale, String deviceClass) {
        return confirm(requirePrincipalSession(tenantId, projectId, sessionId), command, locale,
                deviceClass);
    }

    public View confirmForBrowser(String sessionId, String accessToken, ConfirmCommand command) {
        return confirmForBrowser(sessionId, accessToken, command, Locale.ENGLISH, "WEB");
    }

    public View confirmForBrowser(String sessionId, String accessToken, ConfirmCommand command,
            Locale locale, String deviceClass) {
        return confirm(requireBrowserSession(sessionId, accessToken), command, locale,
                deviceClass);
    }

    public ProviderSdkAuthorization authorizeProviderSdkForBrowser(String sessionId,
            String accessToken, String method, String deviceClass) {
        return authorizeProviderSdk(requireBrowserSession(sessionId, accessToken), method,
                deviceClass);
    }

    public ProviderSdkAuthorization authorizeProviderSdkForPrincipal(UUID tenantId,
            UUID projectId, String sessionId, String method, String deviceClass) {
        return authorizeProviderSdk(requirePrincipalSession(tenantId, projectId, sessionId), method,
                deviceClass);
    }

    private ProviderSdkAuthorization authorizeProviderSdk(CheckoutSessionRepository.Record session,
            String requestedMethod, String deviceClass) {
        String method = normalizeMethod(requestedMethod);
        PaymentIntent intent = payments.get(session.tenantId(), session.paymentIntentId());
        requireAuthoritativeSnapshot(session, intent);
        if (!"OPEN".equals(status(session, intent)) || !session.allowedMethods().contains(method)
                || !intent.permitsMethod(method)) {
            throw new IllegalArgumentException("checkout session cannot authorize this payment method");
        }
        CapabilityResolver.Decision capability = methodDecisions(session, intent, deviceClass)
                .stream().filter(value -> value.method().equals(method)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("payment method capability is unknown"));
        if (!capability.eligible()) {
            throw new IllegalArgumentException("payment method is currently unavailable");
        }
        CheckoutProviderSdkSource.Selection selection = providerSdkSource.select(
                new CheckoutProviderSdkSource.Request(session.tenantId(), session.projectId(),
                        session.merchantId(), method, session.allowedMethods(),
                        session.amountMinor(), session.currency(), intent.region(),
                        normalizeDeviceClass(deviceClass), clock.instant()))
                .orElseThrow(() -> new PaymentCoreException("NO_ELIGIBLE_PROVIDER",
                        "provider SDK capability is unavailable"));
        if (!selection.method().equals(method)) {
            throw new IllegalStateException("provider SDK source returned a mismatched method");
        }
        return new ProviderSdkAuthorization(session.sessionId(), session.tenantId(),
                session.projectId(), session.merchantId(), session.paymentIntentId(), method,
                selection.providerAccountId(), selection.provider(), selection.capabilityVersion(),
                CanonicalPayload.sha256Hex(Map.of("business_order_no", session.businessOrderNo())),
                authoritativeSnapshotDigest(session), session.expiresAt());
    }

    private View confirm(CheckoutSessionRepository.Record session, ConfirmCommand command,
            Locale locale, String deviceClass) {
        Objects.requireNonNull(command, "command");
        String method = normalizeMethod(command.method());
        if (!session.allowedMethods().contains(method)) {
            throw new IllegalArgumentException("payment method is outside the signed session");
        }
        PaymentIntent intent = payments.get(session.tenantId(), session.paymentIntentId());
        if (!"OPEN".equals(status(session, intent))) {
            throw new IllegalArgumentException("checkout session is not open");
        }
        CapabilityResolver.Decision selected = methodDecisions(session, intent, deviceClass)
                .stream().filter(decision -> decision.method().equals(method)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "payment method capability is unknown"));
        if (!selected.eligible()) {
            throw new IllegalArgumentException("payment method is currently unavailable");
        }
        String reference = command.paymentMethodReference();
        if (reference == null) {
            if (!allowSyntheticPaymentReference) {
                throw new IllegalArgumentException(
                        "a PSP- or wallet-issued payment method reference is required");
            }
            reference = "wallet://hosted-checkout/" + session.sessionId() + "/" + method;
        }
        String fingerprint = command.fingerprint();
        if (fingerprint == null) {
            fingerprint = "checkout-" + CanonicalPayload.sha256Hex(Map.of(
                    "session_id", session.sessionId(), "method", method)).substring(0, 32);
        }
        var result = payments.confirm(new ConfirmationCommand(session.tenantId(),
                session.paymentIntentId(), PaymentMethodReference.parse(method, reference,
                        fingerprint), command.idempotencyKey(), command.correlationId(),
                session.returnRouteId(), command.providerParameters()));
        return view(session, result.clientAction(), locale, deviceClass);
    }

    private View view(CheckoutSessionRepository.Record session) {
        return view(session, Locale.ENGLISH, "WEB");
    }

    private View view(CheckoutSessionRepository.Record session, Locale locale,
            String deviceClass) {
        return view(session, Map.of(), locale, deviceClass);
    }

    private View view(CheckoutSessionRepository.Record session,
            Map<String, String> nextAction, Locale requestedLocale, String deviceClass) {
        Locale locale = requestedLocale == null ? Locale.ENGLISH : requestedLocale;
        PaymentIntent intent = payments.get(session.tenantId(), session.paymentIntentId());
        String status = status(session, intent);
        List<MethodView> methods = new ArrayList<>();
        methodDecisions(session, intent, deviceClass).stream()
                .sorted(Comparator.comparing((CapabilityResolver.Decision decision) ->
                        !decision.eligible()).thenComparing(CapabilityResolver.Decision::method))
                .forEach(decision -> {
                    boolean eligible = "OPEN".equals(status) && decision.eligible();
                    String reason = !"OPEN".equals(status) ? "SESSION_NOT_OPEN"
                            : String.join(",", decision.reasons());
                    methods.add(new MethodView(decision.method(),
                            localization.methodLabel(locale, decision.method()), eligible,
                            reason));
                });
        return new View(session.sessionId(), intent.id().toString(), intent.externalReference(),
                intent.amount().amountMinor(), intent.amount().currency().code(),
                session.returnRouteId(), session.expiresAt(), status,
                localization.formatMoney(intent.amount().amountMinor(),
                        intent.amount().currency().code(), locale),
                localization.localeTag(locale), localization.direction(locale), methods,
                nextAction, localization.catalogVersion(),
                localization.browserMessages(locale, status));
    }

    private List<CapabilityResolver.Decision> methodDecisions(
            CheckoutSessionRepository.Record session, PaymentIntent intent, String deviceClass) {
        List<CapabilityResolver.Decision> resolved = capabilitySource.resolve(
                new CheckoutCapabilitySource.Request(session.tenantId(), session.projectId(),
                        session.merchantId(), session.allowedMethods(), intent.amount().amountMinor(),
                        intent.amount().currency().code(), intent.region(),
                        normalizeDeviceClass(deviceClass), clock.instant()));
        Map<String, CapabilityResolver.Decision> byMethod = new java.util.LinkedHashMap<>();
        resolved.forEach(decision -> {
            if (!session.allowedMethods().contains(decision.method())
                    || byMethod.putIfAbsent(decision.method(), decision) != null) {
                throw new IllegalStateException("capability source returned an invalid decision");
            }
        });
        session.allowedMethods().forEach(method -> byMethod.putIfAbsent(method,
                new CapabilityResolver.Decision(method, false, List.of("CAPABILITY_UNKNOWN"))));
        return List.copyOf(byMethod.values());
    }

    private CheckoutSessionRepository.Record requirePrincipalSession(UUID tenantId, UUID projectId,
            String sessionId) {
        CheckoutSessionRepository.Record session = repository.find(tenantId, sessionId).orElse(null);
        if (session == null || !session.projectId().equals(projectId)) {
            throw new SecurityException("unknown checkout session");
        }
        return session;
    }

    private CheckoutSessionRepository.Record requireBrowserSession(String sessionId,
            String accessToken) {
        UUID tenantId = signer.tenantClaim(accessToken);
        CheckoutSessionRepository.Record session = repository.find(tenantId, sessionId)
                .orElseThrow(() -> new SecurityException("unknown checkout session"));
        if (!signer.verify(session, accessToken)) {
            throw new SecurityException("invalid checkout session token");
        }
        return session;
    }

    private URI checkoutUrl(String sessionId, String token) {
        // Fragments are never sent in HTTP request targets or Referer headers. The browser
        // copies this short-lived token into sessionStorage and immediately clears history.
        return URI.create(publicBaseUri + "#session=" + encode(sessionId)
                + "&token=" + encode(token));
    }

    private Created created(CheckoutSessionRepository.Record session) {
        String token = signer.token(session);
        return new Created(session.sessionId(), session.paymentIntentId().toString(),
                session.expiresAt(),
                checkoutUrl(session.sessionId(), token), status(session,
                        payments.get(session.tenantId(), session.paymentIntentId())));
    }

    private static void requireSameRequest(CheckoutSessionRepository.Record session,
            String requestDigest) {
        if (!MessageDigest.isEqual(session.requestDigest().getBytes(StandardCharsets.US_ASCII),
                requestDigest.getBytes(StandardCharsets.US_ASCII))) {
            throw new IllegalArgumentException(
                    "idempotency key was already used with a different checkout request");
        }
    }

    private static void requireAuthoritativeSnapshot(CheckoutSessionRepository.Record session,
            PaymentIntent intent) {
        boolean identityMatches = session.tenantId().equals(intent.tenantId())
                && session.projectId().equals(intent.projectId())
                && session.merchantId().equals(intent.merchantId())
                && session.businessOrderNo().equals(intent.externalReference())
                && session.amountMinor() == intent.amount().amountMinor()
                && session.currency().equals(intent.amount().currency().code())
                && session.allowedMethods().equals(intent.allowedMethods());
        if (!identityMatches || !checkoutRequestDigestMatches(session)) {
            throw new SecurityException("checkout immutable snapshot does not match its payment intent");
        }
    }

    private static boolean checkoutRequestDigestMatches(CheckoutSessionRepository.Record session) {
        Map<String, Object> fields = new java.util.LinkedHashMap<>();
        fields.put("tenant_id", session.tenantId().toString());
        fields.put("project_id", session.projectId().toString());
        fields.put("merchant_id", session.merchantId().toString());
        fields.put("business_order_no", session.businessOrderNo());
        fields.put("amount", session.amountMinor());
        fields.put("currency", session.currency());
        fields.put("return_route_id", session.returnRouteId());
        fields.put("device_context_digest", session.deviceContextDigest());
        if (sameDigest(session.requestDigest(), CanonicalPayload.sha256Hex(fields))) {
            return true;
        }
        // A constrained create adds payment_method to the request fingerprint. The
        // stored allowed-method snapshot is already immutable and equal to the intent;
        // a singleton therefore reconstructs that exact additive field. Accepting the
        // legacy form above keeps pre-upgrade sessions readable.
        if (session.allowedMethods().size() != 1) {
            return false;
        }
        fields.put("payment_method", session.allowedMethods().iterator().next());
        return sameDigest(session.requestDigest(), CanonicalPayload.sha256Hex(fields));
    }

    private static boolean sameDigest(String left, String right) {
        return MessageDigest.isEqual(left.getBytes(StandardCharsets.US_ASCII),
                right.getBytes(StandardCharsets.US_ASCII));
    }

    private static String authoritativeSnapshotDigest(CheckoutSessionRepository.Record session) {
        return CanonicalPayload.sha256Hex(Map.ofEntries(
                Map.entry("session_id", session.sessionId()),
                Map.entry("tenant_id", session.tenantId().toString()),
                Map.entry("project_id", session.projectId().toString()),
                Map.entry("merchant_id", session.merchantId().toString()),
                Map.entry("payment_intent_id", session.paymentIntentId().toString()),
                Map.entry("request_digest", session.requestDigest()),
                Map.entry("expires_at", session.expiresAt().toString()),
                Map.entry("nonce", session.nonce())));
    }

    private String status(CheckoutSessionRepository.Record session, PaymentIntent intent) {
        if (!clock.instant().isBefore(session.expiresAt())) {
            return "EXPIRED";
        }
        return switch (intent.state()) {
            case CREATED -> "OPEN";
            case REQUIRES_ACTION, AUTHORIZED -> "PENDING";
            case CAPTURED -> "SUCCEEDED";
            case FAILED -> "FAILED";
            case CANCELED -> "CANCELED";
            case EXPIRED -> "EXPIRED";
        };
    }

    private static URI validatePublicBase(URI value) {
        Objects.requireNonNull(value, "publicBaseUri");
        if (!value.isAbsolute() || value.getHost() == null || value.getUserInfo() != null
                || value.getFragment() != null
                || !("https".equalsIgnoreCase(value.getScheme())
                || ("http".equalsIgnoreCase(value.getScheme())
                && ("127.0.0.1".equals(value.getHost()) || "localhost".equals(value.getHost()))))) {
            throw new IllegalArgumentException("checkout public base must be HTTPS or loopback HTTP");
        }
        return value;
    }

    private static String normalizeMethod(String value) {
        requireText(value, "payment method", 64);
        String normalized = value.toLowerCase(Locale.ROOT);
        if (!normalized.matches("[a-z0-9][a-z0-9._-]{0,63}")) {
            throw new IllegalArgumentException("payment method is invalid");
        }
        return normalized;
    }

    private static String normalizeDeviceContext(String value) {
        if (value == null || value.isBlank()) {
            return DEFAULT_DEVICE_CONTEXT;
        }
        if (!value.matches("[A-Za-z0-9._:-]{16,128}")) {
            throw new IllegalArgumentException("device context digest is invalid");
        }
        return value;
    }

    private static String normalizeDeviceClass(String value) {
        String normalized = value == null ? "WEB" : value.toUpperCase(Locale.ROOT);
        if (!Set.of("WEB", "IOS", "ANDROID", "FLUTTER").contains(normalized)) {
            throw new IllegalArgumentException("checkout device class is invalid");
        }
        return normalized;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static void requireText(String value, String name, int maxLength) {
        if (value == null || value.isBlank() || value.length() > maxLength) {
            throw new IllegalArgumentException(name + " is required and too long");
        }
    }
}
