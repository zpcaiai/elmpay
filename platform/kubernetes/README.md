# Production Kubernetes controls

`static-bundle.json` contains resources that do not depend on an application
image: restricted namespace enforcement, tokenless service accounts, Services,
PDBs, default-deny/allow-list network policy, and strict mesh mTLS identity.

Workload Deployments are rendered by `tools/runtime/control.py render-kubernetes`
only after a release input supplies digest-pinned images for every service. The
renderer applies `workload-policy.json` and refuses tags, missing digests, unknown
services, or security overrides. This keeps an unbuilt image from becoming a
plausible-looking production manifest.
