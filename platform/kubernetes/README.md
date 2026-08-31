# Production Kubernetes controls

`static-bundle.json` contains resources that do not depend on an application
image: restricted namespace enforcement, tokenless service accounts, Services,
PDBs, default-deny/allow-list network policy, and strict mesh mTLS identity.

Workload Deployments are rendered by `tools/runtime/control.py render-kubernetes`
only after a release input supplies digest-pinned images for every service. The
renderer applies `workload-policy.json` and refuses tags, missing digests, unknown
services, or security overrides. This keeps an unbuilt image from becoming a
plausible-looking production manifest.

The exact six-image build inventory is `platform/oci/product-images.json`.
`platform/kubernetes/image-admission-policy.json` binds the allowed registry,
GitHub OIDC signer identity, SLSA/CycloneDX subjects, vulnerability scan and
hardened workload fields. An external admission controller must enforce it;
source validation alone is not target-cluster admission evidence. The terminal
release gate additionally requires the exact final product-image index and an
independently signed production-cluster attestation for the same image set and
admission-policy digest.

`tools/platform_control.py render-service-controls` renders a ServiceAccount,
PDB, HPA, default-deny NetworkPolicy and mesh AuthorizationPolicy for every
workload declared in `workload-policy.json`; it emits a Service only when the
workload explicitly exposes a business listener. `service-callers.json` must
cover the exact workload set and a health-only workload cannot accept or make a
business service call.

The exact source inventory includes `edge-gateway`, `risk-engine`,
`worker-scheduler`, and `webhook-processor` Java entrypoints plus the
`checkout-web` and `admin-web` package start commands. Checkout-web starts its
production HTTP listener behind the cluster ingress; admin-web starts its HTTPS
listener. Edge-gateway and risk-engine expose only
TLS 1.3 mutual-TLS business listeners on `https:8443`, each with an independent
probe-only listener (`health:8081` and `health:9081`, respectively). The worker has three replicas and only a
probe listener on `health:8081`; `exposeService:false`, an empty ingress allow
list and an empty mesh authorization rule prevent it from becoming a business
endpoint. Kubelet probes target the Pod directly and no Service publishes a
separate health port; every separate health listener is explicitly excluded from mesh
inbound capture while all Pod-to-Pod ingress remains denied by NetworkPolicy.
Target-CNI admission tests must still confirm the documented
kubelet-to-Pod probe behavior.

The same edge TLS listener owns the internal Admin Action intake and status API;
no placeholder mutation service is declared. Mesh callers allow only
`admin-web`, and the admin workload's egress allow-list names the exact
`edge-gateway-internal` destination. Application authorization requires the
sole expected `spiffe://elmpay.example/admin-web` URI SAN from the TLS session
and rejects forwarded identity headers. Approved actions are durable,
digest-bound domain commands: edge returns pending/unknown state and the owning
payment, risk, or rollout consumer applies the effect and receipt atomically.
Edge never directly mutates another domain's business tables. Database
passwords and client keys remain read-only Secret mounts. This source wiring
does not establish target-cluster mesh, human-review or rollout evidence.

Risk evaluation is a separate three-replica workload. Edge is its only mesh
caller and its endpoint is an immutable exact Service FQDN, not tenant-supplied
configuration. The risk workload has database-only plus two exact TLS egress
destinations (`risk-signal` and `risk-model`), each bound to an exact namespace,
Service and Pod selector. Edge shares one immutable 300 ms monotonic deadline
across nonce issuance and decision retrieval; each of the two sequential risk
dependencies has an immutable 100 ms timeout, keeping the complete call inside
the topology budget without restarting that budget at each hop. Signal/model
failures or stale evidence fail closed;
mounted server, client, database and governance material cannot fall back to
environment secrets or HMAC credentials.

The webhook processor is likewise a three-replica, health-only workload with no
Service or business callers. Each replica derives its lease owner from downward-API
`metadata.name`, processes a bounded fair page of tenants, and has database-only
egress to the selected CloudNativePG endpoint. Its password and PostgreSQL mutual-TLS
identity are read from read-only Secret files; no callback body, provider credential,
or inline database credential enters its ConfigMap or environment.

Repository validation resolves each source path, proves that the start command
reaches the declared entrypoint, and rejects a workload whose probe handler is
absent. Inline and externally supplied ConfigMap values are mutually exclusive;
external values are projected with individual `configMapKeyRef` entries rather
than `envFrom`, and secret-looking keys are rejected in both fixed and ConfigMap
configuration. The renderer pins production modes and emits immutable,
non-secret ConfigMaps. Worker lease identity and Kafka client identity come from
the downward API `metadata.name`, so replicas cannot share a fixed holder ID.
Database password, database CA/client certificate/private key and Kafka PKCS12
identity/trust material are mounted read-only from named Secrets with mode
`0440`; none is imported with `secretRef` environment variables. Missing files
therefore prevent startup rather than selecting a sandbox/default mode.
The worker ledger path uses `read_committed`, manual offsets and the one governed
payment-event topic; readiness stays false without an active Kafka assignment
and a recent successful poll. An offset is never committed before the matching
inbox, aggregate-revision fence and balanced ledger entries commit together.

`static-bundle.json` is a managed output of `render-service-controls`, not an
authoritative hand-written manifest. During the current resource gate it still
contains the prior rendering and must be regenerated after the
gate; the exact-inventory test intentionally reports that drift until then. It covers
east-west identity and default-deny policy only; a production north-south Istio
gateway and its independently reviewed AuthorizationPolicy must be supplied by
the target-cluster release configuration before either public service can be
accepted. `render-data-plane` renders the two-region
CloudNativePG, Strimzi Kafka and Redis Failover resources from
`data-plane-policy.json`, using encrypted retained storage, synchronous database
writes, immutable backups, TLS listeners, Kafka ISR fencing and Redis
append-only durability. Applying those CRDs still requires the corresponding
production operators, IAM roles, secret synchronization and independent DR
evidence.

`tools/render_egress_policy.py` renders the separate outbound boundary from
`egress-policy.json`. It requires exact workload coverage and emits an egress
default deny, pod/CIDR NetworkPolicies, exact DNS/FQDN Cilium policies, Istio
`REGISTRY_ONLY` sidecars, and TLS-only external ServiceEntries. Internal APIs,
risk dependencies, PSP, database, Kafka, Redis, KMS and OTel destinations are
enumerated; wildcard FQDNs, broad
CIDRs, arbitrary DNS resolvers and undeclared destinations fail validation.
Applying this bundle requires Cilium DNS proxying and Istio to be installed and
validated in the target cluster. Worker egress is limited to the selected
CloudNativePG Pods on TLS 5432 and Strimzi broker Pods on mTLS 9093, plus the
declared kube-dns Pods; broker bootstrap/headless names are exact, namespace
scoped and wildcard-free. Internal egress target workload, Service, namespace,
selector, mesh caller and runtime endpoint must all agree before rendering.
Local source/render validation is not production
Kubernetes, multi-region DR or certification evidence.
