"""B24 — an executable tenant lifecycle and capability model.

The state machine is the easy half. The half that causes incidents is the
capability matrix: what a tenant can still do in each state. Two answers here
are counter-intuitive and both are enforced:

* a **suspended** tenant can still refund, still receive provider callbacks and
  still settle. Suspension stops *new* money. An implementation that switches
  everything off strands the payers of a suspended merchant — their money has
  already left, and the only route back is a refund the platform just disabled;
* a **closed** tenant can do nothing at all, including reading its own data,
  because its key is gone. The ledger and the audit trail survive, but they
  belong to the platform's record of what it did, not to the tenant.

Environments are modelled as a hard partition: :func:`credential_valid` refuses
a credential minted for one environment in any other, with no override, because
every "just for debugging" override in this area eventually meets real money.
"""
from __future__ import annotations

from dataclasses import dataclass, field

DRAFT, ACTIVE, SUSPENDED, OFFBOARDING, CLOSED = (
    "draft", "active", "suspended", "offboarding", "closed")

DENY_UNKNOWN_STATE = "DENY_UNKNOWN_STATE"
DENY_NOT_ALLOWED = "DENY_NOT_ALLOWED"
DENY_WRONG_ENVIRONMENT = "DENY_WRONG_ENVIRONMENT"
DENY_CROSS_TENANT = "DENY_CROSS_TENANT"
DENY_TRANSITION = "DENY_TRANSITION"
DENY_REQUIREMENT = "DENY_REQUIREMENT"
DENY_QUOTA = "DENY_QUOTA"


class RegistryRefused(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class Credential:
    id: str
    tenant_id: str
    project_id: str
    environment: str


@dataclass
class Tenant:
    id: str
    organisation_id: str
    state: str = DRAFT
    projects: tuple[str, ...] = ()
    kek_destroyed: bool = False
    history: list[dict] = field(default_factory=list)


class Registry:
    """The registry as the platform would enforce it, minus the storage."""

    def __init__(self, model: dict) -> None:
        self.model = model
        self.lifecycle = model["lifecycle"]
        self.transitions = {(t["from"], t["to"]): set(t["requires"])
                            for t in self.lifecycle["transitions"]}
        self.capabilities = {row["state"]: row for row in model["capability_matrix"]}
        self.quotas = {q["id"]: q for q in model["quotas"]}
        self.environments = {e["id"]: e for e in model["environments"]}
        self.tenants: dict[str, Tenant] = {}
        self.usage: dict[tuple[str, str], int] = {}

    # -- lifecycle --------------------------------------------------------
    def register(self, tenant_id: str, organisation_id: str) -> Tenant:
        tenant = Tenant(id=tenant_id, organisation_id=organisation_id,
                        state=self.lifecycle["initial"])
        self.tenants[tenant_id] = tenant
        return tenant

    def transition(self, tenant_id: str, target: str, *, satisfied: set[str],
                   actor: str) -> Tenant:
        tenant = self.tenants.get(tenant_id)
        if tenant is None:
            raise RegistryRefused(DENY_UNKNOWN_STATE, tenant_id)
        required = self.transitions.get((tenant.state, target))
        if required is None:
            raise RegistryRefused(DENY_TRANSITION, f"{tenant.state} -> {target}")
        missing = required - satisfied
        if missing:
            raise RegistryRefused(DENY_REQUIREMENT, f"missing {sorted(missing)}")
        tenant.history.append({"from": tenant.state, "to": target, "actor": actor})
        tenant.state = target
        if target == CLOSED:
            # Closing is where the key goes. Everything the tenant could still
            # read stops being readable at this exact point, by construction.
            tenant.kek_destroyed = True
        return tenant

    # -- capabilities -----------------------------------------------------
    def may(self, tenant_id: str, capability: str) -> bool:
        tenant = self.tenants.get(tenant_id)
        if tenant is None:
            raise RegistryRefused(DENY_UNKNOWN_STATE, tenant_id)
        row = self.capabilities.get(tenant.state)
        if row is None or capability not in row:
            raise RegistryRefused(DENY_UNKNOWN_STATE, f"{tenant.state}/{capability}")
        return bool(row[capability])

    def require(self, tenant_id: str, capability: str) -> str:
        if not self.may(tenant_id, capability):
            raise RegistryRefused(DENY_NOT_ALLOWED,
                                  f"{capability} is not allowed while "
                                  f"{self.tenants[tenant_id].state}")
        return "OK"

    # -- boundaries -------------------------------------------------------
    def credential_valid(self, credential: Credential, *, tenant_id: str,
                         environment: str) -> str:
        if credential.tenant_id != tenant_id:
            raise RegistryRefused(DENY_CROSS_TENANT,
                                  f"credential belongs to {credential.tenant_id}")
        if credential.environment != environment:
            raise RegistryRefused(DENY_WRONG_ENVIRONMENT,
                                  f"credential is for {credential.environment}, not "
                                  f"{environment}")
        if environment not in self.environments:
            raise RegistryRefused(DENY_WRONG_ENVIRONMENT, environment)
        return "OK"

    def handles_real_money(self, environment: str) -> bool:
        entry = self.environments.get(environment)
        if entry is None:
            raise RegistryRefused(DENY_WRONG_ENVIRONMENT, environment)
        return bool(entry["handles_real_money"])

    # -- quotas -----------------------------------------------------------
    def consume(self, scope_id: str, quota_id: str, amount: int = 1,
                limit: int | None = None) -> int:
        quota = self.quotas.get(quota_id)
        if quota is None:
            raise RegistryRefused(DENY_QUOTA, f"unknown quota {quota_id}")
        ceiling = quota["default"] if limit is None else limit
        if limit is not None and limit > quota["hard_ceiling"]:
            raise RegistryRefused(DENY_QUOTA,
                                  f"{limit} exceeds the hard ceiling {quota['hard_ceiling']}")
        key = (scope_id, quota_id)
        used = self.usage.get(key, 0) + amount
        if used > ceiling:
            raise RegistryRefused(DENY_QUOTA, f"{quota_id} exhausted at {ceiling}")
        self.usage[key] = used
        return used

    def reset(self, scope_id: str, quota_id: str) -> None:
        self.usage.pop((scope_id, quota_id), None)
