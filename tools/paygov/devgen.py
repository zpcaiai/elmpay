"""B04 — generate the local development platform from its declaration.

``platform/dev/compose.yaml`` and its companions are generated from
``governance/dev-platform.json`` so that ports, images, health checks and
environment variables cannot drift away from the declaration the gate checks.
"""
from __future__ import annotations

from pathlib import Path

from .repo import Budget, load_json

DEV = Path("governance/dev-platform.json")
CATALOG = Path("governance/version-catalog.json")
BANNER = ("# GENERATED FILE — do not edit by hand.\n"
          "# Source of truth: governance/dev-platform.json\n"
          "# Regenerate with: python3 scripts/render-dev-platform.py\n")


def _quote(value: str) -> str:
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'


def _image_ref(entry: dict) -> str:
    return f'{entry["source"]}:{entry["version"]}@{entry["digest"]}'


def compose_yaml(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    dev = load_json(root / DEV, budget)
    entries = {e["id"]: e for e in load_json(root / CATALOG, budget)["entries"]}

    lines = [BANNER, "name: elmpay-dev", "", "services:"]
    for service in dev["services"]:
        entry = entries.get(service["image_ref"])
        # A missing catalogue entry is reported by the dev-platform validator;
        # the generator must still produce output rather than crash, otherwise a
        # bad declaration takes the whole gate down instead of failing it.
        image = _image_ref(entry) if entry else f'UNRESOLVED-CATALOGUE-ENTRY:{service["image_ref"]}'
        lines += [f'  {service["id"]}:',
                  f'    image: {image}',
                  f'    # {service["purpose"]} — data: {service["data_classification"]}',
                  "    restart: unless-stopped",
                  "    read_only: false",
                  "    security_opt:",
                  "      - no-new-privileges:true"]
        if service["ports"]:
            lines.append("    ports:")
            for port in service["ports"]:
                bind = port.get("bind", "127.0.0.1")
                mapping = "{}:{}:{}".format(bind, port["host"], port["container"])
                lines.append("      - " + _quote(mapping))
        if service["environment"]:
            lines.append("    environment:")
            for key in sorted(service["environment"]):
                lines.append(f'      {key}: {_quote(service["environment"][key])}')
        if service["volumes"]:
            lines.append("    volumes:")
            for volume in service["volumes"]:
                lines.append(f'      - {volume}')
        lines += ["    healthcheck:",
                  f'      test: ["CMD-SHELL", {_quote(service["healthcheck"])}]',
                  "      interval: 10s", "      timeout: 5s", "      retries: 12"]
        lines.append("")

    for simulator in dev["simulators"]:
        lines += [f'  {simulator["id"]}:',
                  "    build:",
                  "      context: ../..",
                  f'      dockerfile: {simulator["build_context"]}/Dockerfile',
                  f'      args:',
                  f'        PROVIDER: {simulator["provider"]}',
                  f'    # {simulator["purpose"]} — data: {simulator["data_classification"]}',
                  "    restart: unless-stopped",
                  "    security_opt:",
                  "      - no-new-privileges:true",
                  "    ports:"]
        for port in simulator["ports"]:
            bind = port.get("bind", "127.0.0.1")
            mapping = "{}:{}:{}".format(bind, port["host"], port["container"])
            lines.append("      - " + _quote(mapping))
        lines += ["    healthcheck:",
                  f'      test: ["CMD-SHELL", {_quote(simulator["healthcheck"])}]',
                  "      interval: 10s", "      timeout: 5s", "      retries: 12", ""]

    lines.append("volumes:")
    for volume in dev["volumes"]:
        lines.append(f'  {volume}: {{}}')
    return "\n".join(lines).rstrip() + "\n"


def env_example(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    dev = load_json(root / DEV, budget)
    lines = [BANNER,
             "# Local development only. These values are synthetic and must never be reused",
             "# outside local/integration. Production credentials are resolved from",
             "# kms:// or vault:// references at runtime and never live in a .env file.",
             ""]
    for name in dev["secret_env_vars"]:
        lines.append(f'{name}=local-dev-{name.lower().replace("_", "-")}-change-me')
    return "\n".join(lines).rstrip() + "\n"


def dockerfile_for(provider: str):
    """Build a renderer for one provider's simulator image.

    The build context is the repository root so that ``tools/simulator`` can be
    copied in; each provider gets its own Dockerfile so that compose builds are
    independently cacheable and the provider is baked in rather than passed at
    run time.
    """

    def render(root: Path, budget: Budget | None = None) -> str:
        budget = budget or Budget().start()
        entries = {e["id"]: e for e in load_json(root / CATALOG, budget)["entries"]}
        python_version = entries["python-sim"]["version"]
        return BANNER + f"""
# Offline {provider} simulator. Standard library only, no package index needed.
FROM python:{python_version}-slim

WORKDIR /app
COPY tools/simulator /app/tools/simulator
ENV PYTHONPATH=/app
USER 65532:65532
EXPOSE 8080

ENTRYPOINT ["python3", "-m", "tools.simulator.provider_sim", "--provider", "{provider}"]
"""

    return render


def dev_readme(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget().start()
    dev = load_json(root / DEV, budget)
    def _ports(service: dict) -> str:
        return ", ".join("{}→{}".format(p["host"], p["container"]) for p in service["ports"])

    rows = [[s["id"], s["purpose"], _ports(s), s["data_classification"]]
            for s in dev["services"]]
    rows += [[s["id"], s["purpose"], _ports(s), s["data_classification"]]
             for s in dev["simulators"]]
    header = ["服务", "用途", "端口", "数据分类"]
    table = ["| " + " | ".join(header) + " |",
             "| " + " | ".join("---" for _ in header) + " |"]
    table += ["| " + " | ".join(r) + " |" for r in rows]
    return BANNER + f"""
# 本地开发平台（B04）

离线可重复：所有镜像以摘要固定，模拟器只用 Python 标准库构建，无需包索引。

```bash
cp platform/dev/.env.example platform/dev/.env   # 仅本地合成口令
scripts/dev-up.sh                                 # 启动并等待全部 healthy
scripts/dev-up.sh --down                          # 停止
```

{chr(10).join(table)}

## 硬性约束

- 环境仅限 `{'`、`'.join(dev["environments"])}`。
- **禁止**生产凭证、真实卡数据与真实个人信息；所有数据分类必须是 `synthetic`。
- 端口只绑定 `127.0.0.1`，不暴露到局域网。
- 容器统一 `no-new-privileges`，不使用 host 网络，不使用 privileged。
- 模拟器在检测到疑似生产凭证或卡号形状的数据时**拒绝启动/拒绝请求**。
"""


STATIC_TARGETS = {
    "platform/dev/compose.yaml": compose_yaml,
    "platform/dev/.env.example": env_example,
    "platform/dev/README.md": dev_readme,
}


def targets(root: Path, budget: Budget | None = None) -> dict:
    budget = budget or Budget().start()
    dev = load_json(root / DEV, budget)
    result = dict(STATIC_TARGETS)
    for simulator in dev["simulators"]:
        result[f'{simulator["build_context"]}/Dockerfile'] = dockerfile_for(simulator["provider"])
    return result


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in targets(root).items()}
