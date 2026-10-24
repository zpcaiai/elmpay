#!/usr/bin/env python3
"""Fail-closed CodeQL report check and bounded DAST of the real local demo.

This does not close RR-02, replace the original CI, or certify production payments.
The DAST target must be the separately built Java/Node sandbox on loopback.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request
import uuid


def check_sarif(document):
    if document.get("version") != "2.1.0" or not document.get("runs"):
        raise ValueError("missing SARIF runs")
    rule_count = 0
    for run in document["runs"]:
        driver = run.get("tool", {}).get("driver", {})
        # CodeQL 2.27 writes query packs as SARIF tool extensions. Both forms
        # are SARIF 2.1; an empty driver alone still proves no queries ran.
        components = [driver, *run.get("tool", {}).get("extensions", [])]
        rules = [rule for component in components for rule in component.get("rules", [])]
        if driver.get("name") != "CodeQL" or not rules:
            raise ValueError("CodeQL query rules are missing")
        rule_count += len(rules)
        invocations = run.get("invocations", [])
        if not invocations or any(i.get("executionSuccessful") is not True for i in invocations):
            raise ValueError("CodeQL execution was missing or unsuccessful")
        for invocation in invocations:
            for notification in invocation.get("toolExecutionNotifications", []):
                if notification.get("level") == "error":
                    raise ValueError("CodeQL reported an execution error")
        if not isinstance(run.get("results"), list):
            raise ValueError("CodeQL results are absent")
        if run["results"]:
            raise ValueError("CodeQL findings require remediation; suppressions do not waive this gate")
    return {"runs": len(document["runs"]), "rules": rule_count, "findings": 0}


def local_origin(value):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
            or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment
            or parsed.port is None or not 1024 <= parsed.port <= 65535):
        raise ValueError("DAST requires an explicit loopback test origin")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def dast(origin):
    origin = local_origin(origin)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    observations = []

    def probe(label, path, status, body=None, headers=None):
        request_headers = {"accept": "application/json", **(headers or {})}
        if body is not None:
            request_headers.setdefault("content-type", "application/json")
        req = urllib.request.Request(origin + path, headers=request_headers,
            data=None if body is None else json.dumps(body).encode())
        try:
            response = opener.open(req, timeout=8)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(65537)
            if len(raw) > 65536 or response.code != status:
                raise ValueError("DAST status or response bound failed: " + label)
            if (response.headers.get("x-elmpay-demo") != "true"
                    or "no-store" not in response.headers.get("cache-control", "")
                    or response.headers.get("referrer-policy") != "no-referrer"
                    or response.headers.get("x-content-type-options") != "nosniff"):
                raise ValueError("DAST security headers failed: " + label)
            value = json.loads(raw)
            if value.get("demo") is not True or value.get("real_payments") is not False:
                raise ValueError("DAST target is not demo-only")
            observations.append({"check": label, "status": status,
                                 "response_sha256": hashlib.sha256(raw).hexdigest()})
            return value

    health = probe("native readiness", "/health/ready", 200)
    if health.get("status") != "DEMO_READY" or health.get("provider") != "local-sandbox":
        raise ValueError("real native sandbox is not ready")
    # Public Origin stays HTTPS even though this private test transport uses loopback.
    headers = {"origin": "https://elmpay.vercel.app",
               "idempotency-key": "dast-" + str(uuid.uuid4())}
    probe("admin API denied", "/v1/payment_intents", 404)
    probe("query injection denied", "/demo/orders?scenario=succeeded", 400)
    probe("cross-origin creation denied", "/demo/orders", 403,
          {"scenario": "succeeded"}, {**headers, "origin": "https://untrusted.example"})
    probe("money injection denied", "/demo/orders", 400,
          {"scenario": "succeeded", "amount": 1}, headers)
    probe("real channel denied", "/demo/orders", 400,
          {"scenario": "succeeded", "payment_method": "wechat_jsapi"}, headers)
    probe("real scenario denied", "/demo/orders", 400, {"scenario": "live"}, headers)
    probe("missing idempotency denied", "/demo/orders", 400,
          {"scenario": "succeeded"}, {"origin": headers["origin"]})
    probe("bad content type denied", "/demo/orders", 415,
          {"scenario": "succeeded"}, {**headers, "content-type": "text/plain"})
    session = str(uuid.uuid4())
    probe("anonymous session denied", "/api/checkout/sessions/" + session, 401)
    probe("oversized body denied", "/demo/orders", 413,
          {"scenario": "succeeded", "padding": "x" * 5000}, headers)
    return {"target": origin, "checks": observations, "real_payments": False,
            "scope": "bounded local Java/Node sandbox ingress DAST; not production certification"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("sarif", "dast"))
    parser.add_argument("target")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    if args.mode == "sarif":
        directory = Path(args.target)
        paths = sorted(directory.glob("*.sarif"))
        if {p.name for p in paths} != {"java.sarif", "javascript.sarif", "python.sarif"}:
            raise ValueError("all three declared CodeQL language reports are required")
        result = {str(p): {**check_sarif(json.loads(p.read_text())),
                            "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths}
    else:
        result = dast(args.target)
    report = {"mode": args.mode, "pid": os.getpid(), "executed": True, "result": "PASS",
              "source_sha": os.environ.get("GITHUB_SHA"), "details": result}
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
