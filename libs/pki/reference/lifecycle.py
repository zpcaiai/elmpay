"""B21 — an executable certificate and key lifecycle.

The property this module exists to demonstrate is the overlap window. During a
rotation there is a period where **both** the retiring material and its
replacement must verify, because the holders of the old one — in-flight tokens,
a provider's cached JWKS, a pod that has not restarted — do not all switch at
the same instant. A rotation without that window is a rotation that requires
downtime, and a rotation that requires downtime is one that gets postponed until
the certificate expires on its own.

Everything else here is the boring part that actually causes outages: expiry,
renewal margins, failed automated renewals escalating to a human, revocation
taking effect immediately, and a CAA policy that refuses an issuer we never
authorised.

Time is passed in explicitly as an integer day number. There is no clock, no
network and no X.509 parsing: this is the *lifecycle*, not the cryptography.
"""
from __future__ import annotations

from dataclasses import dataclass, field

OK = "OK"
RENEW_DUE = "RENEW_DUE"
EXPIRED = "EXPIRED"
REVOKED = "REVOKED"
UNKNOWN = "UNKNOWN"
UNAUTHORISED_ISSUER = "UNAUTHORISED_ISSUER"


class LifecycleError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class Version:
    """One issued instance of a material."""

    serial: int
    issued_day: int
    expires_day: int
    retired_day: int | None = None   # end of its overlap window, once superseded
    revoked_day: int | None = None

    def accepts(self, day: int) -> bool:
        if self.revoked_day is not None and day >= self.revoked_day:
            return False
        if day < self.issued_day or day >= self.expires_day:
            return False
        if self.retired_day is not None and day >= self.retired_day:
            return False
        return True


@dataclass
class Material:
    id: str
    validity_days: int
    renew_before_days: int
    overlap_days: int
    automated_renewal: bool
    issuer: str
    versions: list[Version] = field(default_factory=list)
    failed_renewals: int = 0

    def issue(self, day: int) -> Version:
        serial = len(self.versions) + 1
        version = Version(serial=serial, issued_day=day,
                          expires_day=day + self.validity_days)
        self.versions.append(version)
        return version

    def current(self) -> Version:
        if not self.versions:
            raise LifecycleError(UNKNOWN, f"{self.id} has never been issued")
        return self.versions[-1]

    def rotate(self, day: int) -> Version:
        """Issue the replacement and start the overlap window on the old one.

        The retiring version keeps verifying for ``overlap_days``. This is the
        whole point: the switch is a window, not an instant.
        """
        old = self.current()
        retired = min(day + self.overlap_days, old.expires_day)
        self.versions[-1] = Version(serial=old.serial, issued_day=old.issued_day,
                                    expires_day=old.expires_day, retired_day=retired,
                                    revoked_day=old.revoked_day)
        return self.issue(day)

    def revoke(self, serial: int, day: int) -> None:
        """Revocation is immediate. An overlap window does not protect it."""
        for index, version in enumerate(self.versions):
            if version.serial == serial:
                self.versions[index] = Version(serial=version.serial,
                                               issued_day=version.issued_day,
                                               expires_day=version.expires_day,
                                               retired_day=version.retired_day,
                                               revoked_day=day)
                return
        raise LifecycleError(UNKNOWN, f"{self.id} has no version {serial}")

    def accepting(self, day: int) -> list[int]:
        """Serials that verify on this day — plural, during an overlap."""
        return [v.serial for v in self.versions if v.accepts(day)]

    def status(self, day: int) -> str:
        live = [v for v in self.versions if v.accepts(day)]
        if not live:
            latest = self.versions[-1] if self.versions else None
            if latest is None:
                return UNKNOWN
            if latest.revoked_day is not None and day >= latest.revoked_day:
                return REVOKED
            return EXPIRED
        newest = max(live, key=lambda v: v.serial)
        if newest.expires_day - day <= self.renew_before_days:
            return RENEW_DUE
        return OK

    def record_renewal_failure(self) -> int:
        self.failed_renewals += 1
        return self.failed_renewals

    def record_renewal_success(self) -> None:
        self.failed_renewals = 0


@dataclass
class Domain:
    name: str
    registrar_lock: bool
    dnssec: bool
    caa_records: tuple[str, ...]
    expires_day: int
    renew_before_days: int

    def authorises(self, issuer: str) -> bool:
        return issuer in self.caa_records

    def status(self, day: int) -> str:
        if day >= self.expires_day:
            return EXPIRED
        if self.expires_day - day <= self.renew_before_days:
            return RENEW_DUE
        return OK


class Estate:
    """The whole estate: materials, domains, alerting and recovery policy."""

    def __init__(self, model: dict) -> None:
        self.model = model
        self.alerting = model["alerting"]
        self.recovery = model["recovery"]
        self.escalate_after = int(self.alerting["escalate_after_failed_renewals"])
        self.materials: dict[str, Material] = {}
        self.domains: dict[str, Domain] = {}
        for entry in model["materials"]:
            self.materials[entry["id"]] = Material(
                id=entry["id"], validity_days=entry["validity_days"],
                renew_before_days=entry["renew_before_days"],
                overlap_days=entry["overlap_days"],
                automated_renewal=entry["automated_renewal"], issuer=entry["issuer"])
        for entry in model["domains"]:
            self.domains[entry["name"]] = Domain(
                name=entry["name"], registrar_lock=entry["registrar_lock"],
                dnssec=entry["dnssec"], caa_records=tuple(entry["caa_records"]),
                expires_day=entry["expires_in_days"],
                renew_before_days=entry["renew_before_days"])

    def issue_all(self, day: int = 0) -> None:
        for material in self.materials.values():
            material.issue(day)

    def verify(self, material_id: str, serial: int, day: int) -> str:
        material = self.materials.get(material_id)
        if material is None:
            raise LifecycleError(UNKNOWN, material_id)
        if serial in material.accepting(day):
            return OK
        for version in material.versions:
            if version.serial != serial:
                continue
            if version.revoked_day is not None and day >= version.revoked_day:
                raise LifecycleError(REVOKED, f"{material_id} v{serial}")
            raise LifecycleError(EXPIRED, f"{material_id} v{serial}")
        raise LifecycleError(UNKNOWN, f"{material_id} v{serial}")

    def accept_issued_certificate(self, domain: str, issuer: str) -> str:
        """A certificate we did not ask for is the first sign of a takeover."""
        entry = self.domains.get(domain)
        if entry is None:
            raise LifecycleError(UNKNOWN, domain)
        if not entry.authorises(issuer):
            raise LifecycleError(UNAUTHORISED_ISSUER,
                                 f"{issuer} is not in the CAA policy for {domain}")
        return OK

    def due(self, day: int) -> list[str]:
        return sorted(mid for mid, material in self.materials.items()
                      if material.status(day) in {RENEW_DUE, EXPIRED, REVOKED})

    def renewal_failed(self, material_id: str) -> bool:
        """True when this failure must stop being a robot's problem."""
        material = self.materials[material_id]
        return material.record_renewal_failure() >= self.escalate_after

    def recover(self, approvals: int, quorum: int) -> str:
        if self.recovery["quorum_required"] and approvals < quorum:
            raise LifecycleError("QUORUM_NOT_MET",
                                 f"{approvals} approvals, {quorum} required")
        if not self.recovery["rehearsed"]:
            raise LifecycleError("UNREHEARSED",
                                 "the recovery path has never been rehearsed")
        return OK
