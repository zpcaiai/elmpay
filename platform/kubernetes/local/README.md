# Local Kubernetes smoke environment

This overlay runs the real `edge-gateway` local sandbox and `checkout-web` in
one Pod. The checkout talks to the gateway over Pod loopback; no Provider,
cloud, production credential, real card data, or external network is used.

The namespace is deliberately named `elmpay-local`, carries restricted Pod
Security labels, uses a tokenless ServiceAccount, non-root/read-only containers,
bounded resources, and default-deny network policy. Images are local-only and
use `imagePullPolicy: Never`.

```sh
python3 scripts/local-k8s.py build --context orbstack
python3 scripts/local-k8s.py up --context orbstack
python3 scripts/local-k8s.py smoke --context orbstack
python3 scripts/local-k8s.py down --context orbstack
```

Only known desktop Kubernetes contexts are accepted. The driver refuses cloud
or otherwise unrecognized contexts. Build inputs are tag-resolved once, then
rebuilt from immutable base-image digests.

Successful execution is `LOCAL_TESTED` engineering evidence only. It is not a
production Kubernetes attestation, multi-region DR exercise, Provider
certification, UAT approval, PCI assessment, penetration test, merchant
acceptance, or `review.json`, and it never changes `0/128 NOT_CERTIFIED`.
