#!/usr/bin/env python3
"""Build, deploy and exercise the explicitly local ELMPay Kubernetes sandbox."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
LOCAL_KEY = "local-api-secret-for-tests"
LOCAL_CONTEXT = re.compile(r"^(?:orbstack|docker-desktop|rancher-desktop|minikube|kind-[a-z0-9._-]+)$")
EDGE_IMAGE = "elmpay/edge-gateway:local"
CHECKOUT_IMAGE = "elmpay/checkout-web:local"


class LocalKubernetesError(RuntimeError):
    """A local-only safety or execution requirement was not satisfied."""


def run(*command: str, env: dict[str, str] | None = None, capture: bool = False) -> str:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "command failed").strip()
        raise LocalKubernetesError(f"{command[0]} failed: {detail}")
    return (completed.stdout or completed.stderr or "").strip()


def context_server(context: str) -> str:
    if not LOCAL_CONTEXT.fullmatch(context):
        raise LocalKubernetesError(f"refusing non-local Kubernetes context: {context}")
    raw = run(
        "kubectl", "--context", context, "config", "view", "--minify", "-o", "json",
        capture=True,
    )
    document = json.loads(raw)
    clusters = document.get("clusters")
    if not isinstance(clusters, list) or len(clusters) != 1:
        raise LocalKubernetesError("local context must resolve to exactly one cluster")
    server = clusters[0].get("cluster", {}).get("server")
    host = urlparse(server).hostname if isinstance(server, str) else None
    allowed_hosts = {"127.0.0.1", "localhost", "kubernetes.docker.internal"}
    if host not in allowed_hosts and not (host and host.endswith(".orb.local")):
        raise LocalKubernetesError(f"refusing non-loopback Kubernetes API server: {host}")
    return server


def java_environment() -> dict[str, str]:
    environment = dict(os.environ)
    candidate = Path("/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home")
    if candidate.is_dir():
        environment["JAVA_HOME"] = str(candidate)
    version = run(
        str(Path(environment.get("JAVA_HOME", "")) / "bin" / "java")
        if environment.get("JAVA_HOME") else "java",
        "-version",
        env=environment,
        capture=True,
    )
    match = re.search(r'version "(\d+)', version)
    if not match or int(match.group(1)) < 25:
        raise LocalKubernetesError("Java 25 or newer is required for the local image build")
    return environment


def immutable_image(tag: str) -> str:
    run("docker", "pull", tag)
    digests = run("docker", "image", "inspect", tag, "--format", "{{json .RepoDigests}}", capture=True)
    values = json.loads(digests)
    if not isinstance(values, list) or not values or "@sha256:" not in values[0]:
        raise LocalKubernetesError(f"base image did not resolve to a repository digest: {tag}")
    return values[0]


def build() -> None:
    environment = java_environment()
    run(
        "./gradlew", "--no-daemon", "--console=plain", ":apps:edge-gateway:installDist",
        env=environment,
    )
    java_base = immutable_image("eclipse-temurin:25-jre-alpine")
    node_base = immutable_image("node:24-alpine")
    source_commit = run("git", "rev-parse", "HEAD", capture=True)
    manifest_digest = hashlib.sha256(
        (ROOT / "platform/oci/product-images.json").read_bytes()
    ).hexdigest()
    common = (
        "--build-arg", f"SOURCE_COMMIT={source_commit}",
        "--build-arg", f"PRODUCT_IMAGE_MANIFEST_DIGEST={manifest_digest}",
    )
    run(
        "docker", "build", "--file", "platform/oci/java-runtime.Containerfile",
        "--build-arg", f"BASE_IMAGE={java_base}",
        "--build-arg", "APP_DIRECTORY=apps/edge-gateway/build/install/edge-gateway",
        "--build-arg", "MAIN_CLASS_FILE=platform/oci/java-main-classes/edge-gateway.default",
        "--build-arg", "MAIN_CLASS_ALLOWLIST=platform/oci/java-main-classes/edge-gateway.allowlist",
        *common, "--tag", EDGE_IMAGE, ".",
    )
    run(
        "docker", "build", "--file", "platform/oci/checkout-web.Containerfile",
        "--build-arg", f"BASE_IMAGE={node_base}",
        *common, "--tag", CHECKOUT_IMAGE, ".",
    )


def kubectl(context: str, *arguments: str, capture: bool = False) -> str:
    context_server(context)
    return run("kubectl", "--context", context, *arguments, capture=capture)


def up(context: str) -> None:
    kubectl(context, "apply", "-k", "platform/kubernetes/local")
    # Local images intentionally keep stable tags and never leave the desktop
    # daemon, so applying the unchanged Pod template would otherwise retain a
    # previous image ID after a rebuild.
    kubectl(
        context, "-n", "elmpay-local", "rollout", "restart",
        "deployment/elmpay-local-stack",
    )
    kubectl(
        context, "-n", "elmpay-local", "rollout", "status",
        "deployment/elmpay-local-stack", "--timeout=180s",
    )


def smoke(context: str) -> None:
    javascript = r'''
const base = 'http://127.0.0.1:8080';
const request = async (path, options = {}) => {
  const response = await fetch(base + path, options);
  const body = await response.text();
  if (!response.ok) throw new Error(`${path}: ${response.status} ${body}`);
  return JSON.parse(body);
};
const headers = {
  authorization: 'Bearer local-api-secret-for-tests',
  'content-type': 'application/json',
  'x-project-id': '20000000-0000-0000-0000-000000000002',
  'x-request-id': 'local-k8s-request-0001',
  traceparent: '00-11111111111111111111111111111111-2222222222222222-01',
};
const edgeHealthResponse = await fetch('http://127.0.0.1:8090/health/ready');
if (!edgeHealthResponse.ok) throw new Error(`edge health: ${edgeHealthResponse.status}`);
const edgeHealth = await edgeHealthResponse.json();
const checkoutHealthResponse = await fetch('http://127.0.0.1:8088/health/ready');
if (!checkoutHealthResponse.ok) throw new Error(`checkout health: ${checkoutHealthResponse.status}`);
const created = await request('/v1/payment_intents', {
  method: 'POST', headers: {...headers, 'idempotency-key': 'local-k8s-create-0001'},
  body: JSON.stringify({external_reference: 'local-k8s-order-1', amount_minor: 1250,
    currency: 'USD', allowed_methods: ['card'], confirmation_mode: 'automatic',
    region: 'US', ttl_minutes: 60}),
});
const createdReplay = await request('/v1/payment_intents', {
  method: 'POST', headers: {...headers, 'idempotency-key': 'local-k8s-create-0001'},
  body: JSON.stringify({external_reference: 'local-k8s-order-1', amount_minor: 1250,
    currency: 'USD', allowed_methods: ['card'], confirmation_mode: 'automatic',
    region: 'US', ttl_minutes: 60}),
});
const confirmed = await request(`/v1/payment_intents/${created.id}/confirm`, {
  method: 'POST', headers: {...headers, 'idempotency-key': 'local-k8s-confirm-0001'},
  body: JSON.stringify({method: 'card', payment_method_reference: 'psp://local/k8s-reference-1',
    fingerprint: 'fp-local-k8s', approved_return_route_id: 'checkout-complete',
    provider_parameters: {simulation: 'succeeded'}}),
});
const confirmedReplay = await request(`/v1/payment_intents/${created.id}/confirm`, {
  method: 'POST', headers: {...headers, 'idempotency-key': 'local-k8s-confirm-0001'},
  body: JSON.stringify({method: 'card', payment_method_reference: 'psp://local/k8s-reference-1',
    fingerprint: 'fp-local-k8s', approved_return_route_id: 'checkout-complete',
    provider_parameters: {simulation: 'succeeded'}}),
});
const floating = await fetch(base + '/v1/payment_intents', {
  method: 'POST', headers: {...headers, 'idempotency-key': 'local-k8s-float-0001'},
  body: JSON.stringify({external_reference: 'local-k8s-float', amount_minor: 12.5,
    currency: 'USD', allowed_methods: ['card'], confirmation_mode: 'automatic',
    region: 'US', ttl_minutes: 60}),
});
const intent = confirmed.payment_intent;
if (edgeHealth.mode !== 'local' || intent.state !== 'captured'
    || intent.captured_amount_minor !== 1250 || createdReplay.id !== created.id
    || confirmedReplay.payment_intent.id !== intent.id || floating.status !== 400) {
  throw new Error(`unexpected local result: ${JSON.stringify({edgeHealth, created,
    createdReplay, confirmed, confirmedReplay, floatingStatus: floating.status})}`);
}
process.stdout.write(JSON.stringify({status: 'LOCAL_TESTED', edge: edgeHealth.mode,
  checkout: 'ready', paymentIntentState: intent.state,
  capturedAmountMinor: intent.captured_amount_minor,
  idempotentReplay: true, floatingAmountRejected: true,
  certificationStatus: 'NOT_CERTIFIED'}) + '\n');
'''
    pod = kubectl(
        context, "-n", "elmpay-local", "get", "pod",
        "-l", "app.kubernetes.io/name=elmpay-local-stack",
        "-o", "jsonpath={.items[0].metadata.name}", capture=True,
    )
    if not pod:
        raise LocalKubernetesError("local stack Pod is missing")
    kubectl(context, "-n", "elmpay-local", "exec", pod, "-c", "checkout-web", "--", "node", "-e", javascript)


def down(context: str) -> None:
    kubectl(context, "delete", "namespace", "elmpay-local", "--ignore-not-found=true")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("build", "up", "smoke", "down"):
        command = commands.add_parser(name)
        command.add_argument("--context", default="orbstack")
    arguments = parser.parse_args()
    try:
        context_server(arguments.context)
        if arguments.command == "build":
            build()
        elif arguments.command == "up":
            up(arguments.context)
        elif arguments.command == "smoke":
            smoke(arguments.context)
        else:
            down(arguments.context)
        return 0
    except (LocalKubernetesError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "FAILED", "error": str(error),
                          "certificationStatus": "NOT_CERTIFIED"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
