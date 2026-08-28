# Production Kubernetes controls

`static-bundle.json` contains resources that do not depend on an application
image: restricted namespace enforcement, tokenless service accounts, Services,
PDBs, default-deny/allow-list network policy, and strict mesh mTLS identity.

Workload Deployments are rendered by `tools/runtime/control.py render-kubernetes`
only after a release input supplies digest-pinned images for every service. The
renderer applies `workload-policy.json` and refuses tags, missing digests, unknown
services, or security overrides. This keeps an unbuilt image from becoming a
plausible-looking production manifest.

`tools/platform_control.py render-service-controls` renders a ServiceAccount,
Service, PDB, HPA, default-deny NetworkPolicy and mesh AuthorizationPolicy for
every workload declared in `workload-policy.json`; `service-callers.json` must
cover the exact workload set. `render-data-plane` renders the two-region
CloudNativePG, Strimzi Kafka and Redis Failover resources from
`data-plane-policy.json`, using encrypted retained storage, synchronous database
writes, immutable backups, TLS listeners, Kafka ISR fencing and Redis
append-only durability. Applying those CRDs still requires the corresponding
production operators, IAM roles, secret synchronization and independent DR
evidence.

`tools/render_egress_policy.py` renders the separate outbound boundary from
`egress-policy.json`. It requires exact workload coverage and emits an egress
default deny, pod/CIDR NetworkPolicies, exact DNS/FQDN Cilium policies, Istio
`REGISTRY_ONLY` sidecars, and TLS-only external ServiceEntries. PSP, database,
Kafka, Redis, KMS and OTel destinations are enumerated; wildcard FQDNs, broad
CIDRs, arbitrary DNS resolvers and undeclared destinations fail validation.
Applying this bundle requires Cilium DNS proxying and Istio to be installed and
validated in the target cluster; the local renderer is not production evidence.
