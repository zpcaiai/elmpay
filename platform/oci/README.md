# Product OCI release contract

`product-images.json` is the source-of-truth build inventory for all six
production workloads. It does not contain placeholder image digests. The Java,
Node and Node-plus-PostgreSQL-client bases are protected release inputs and
must arrive as non-zero `repository@sha256:<64 hex>` references.

The Java images consume only Gradle `installDist` outputs. They place the
distribution at `/opt/elmpay/app` and start through
`/opt/elmpay/bin/java-main`, which always uses the fixed
`/opt/elmpay/app/lib/*` classpath and `/opt/java/openjdk/bin/java`. Each image
also embeds a read-only default-main file and an exact read-only allowlist;
edge-gateway contains only its gateway and migration entrypoints, worker
contains only its scheduler plus the exact partition/archive GitOps job
entrypoints, and risk/webhook each contain exactly one entrypoint. These
policies are files in the image, not deployment-overridable environment
variables. Kubernetes Jobs reuse the same immutable service digest and launcher; a bare `java
MainClass` invocation is forbidden because it has no image-layout classpath
contract. Checkout and Admin copy no tests or development dependencies. Their
package manifests currently have no dependency sections; Admin's digest-pinned
base contract additionally requires `/usr/bin/psql`.

`scripts/product-image-pipeline.py` separates the evidence states:

1. `source-gate` validates source/build/runtime/admission coverage only.
2. `build` requires pinned base and Buildx executable inputs, creates OCI
   archives with reproducible timestamps and network-disabled Containerfiles,
   rejects any supplied aggregate artifact digest that differs from the
   canonical six-image source tree, and binds the exact `.dockerignore` and
   byte-reviewed Containerfile and Java-launcher contracts. Before invoking
   Buildx it copies only those digest-, size- and mode-bound regular files into
   a new exact context tree through no-follow file descriptors. Buildx never
   receives the mutable repository checkout; the context is revalidated before
   and after every image build. It validates the complete OCI
   descriptor/config/layer/blob chain and merged-rootfs whiteout/link semantics,
   proving each required base executable, launcher and application runtime path
   survives with the required permissions. It emits a clearly labelled partial
   application-file inventory plus SLSA predicates bound to that inspection,
   the exact OCI subject and Buildx executable digest. The partial inventory is
   never accepted as the release SBOM.
3. `scan` requires a pinned Trivy executable and pre-fetched database digest.
   Before analysis it snapshots and re-inspects every OCI archive, then emits
   a vulnerability report and a package-level CycloneDX 1.6 SBOM for those
   exact immutable bytes, both rebound to the exact image digest. The archive
   is rehashed and re-inspected after each Trivy pass, and the same scan
   snapshot is the only source accepted by publication. Missing, empty,
   file-only, stale or failed analysis blocks.
4. `publish` never rebuilds. It snapshots every already-scanned OCI archive,
   verifies all six snapshots before the first registry mutation, and copies
   each snapshot through digest-pinned Skopeo with digest preservation to a
   content-derived `sha256-<digest>` tag. A durable per-image receipt makes a
   partial multi-image run resumable: a deleted tag is recopied from the exact
   snapshot, an already-exact tag is reconciled, and a tag pointing elsewhere
   blocks. Registries do not offer a six-repository transaction, so the
   aggregate publication index is written and marked `VERIFIED` only after all
   six receipts and remote digests are exact.
5. `sign-registry` requires the protected Cosign executable SHA-256, governed
   release, exact source SHA and trusted GitHub OIDC workflow identity. It signs
   each registry digest and attaches the exact full-image SBOM/provenance.
6. `finalize` accepts only the actual exact publication index plus matching
   scan/signature subjects and creates the release index after re-reading every
   bounded evidence file and DSSE predicate to defeat path/symlink or
   between-stage replacement. It also reruns cryptographic signature and
   attestation verification for every registry subject with the release-policy
   version and executable-digest-pinned Cosign; syntactically plausible local
   bundle JSON alone can never finalize. The final index binds Buildx, Trivy,
   scanner DB, Skopeo, Cosign and every intermediate index digest. `verify-release` fail-closes
   unless that exact index, this manifest and the admission policy are bound by
   the signed release manifest.

None of those external phases has been executed merely because its code is
present. Until real build, scan, registry signature, admission-controller and
target-cluster attestations exist, the release stays blocked and certification
remains `NOT_CERTIFIED`.
