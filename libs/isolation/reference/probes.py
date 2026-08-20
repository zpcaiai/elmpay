"""B31 — executable isolation probes.

Every class here exists to be *refused*. The point of the batch is that a test
asserting "tenant A can read tenant A's rows" says nothing about isolation:
delete the predicate and it still passes. So each surface below is modelled so
that the interesting assertion is a denial, and :func:`run_probes` collects
exactly those denials.

The database emulates the shape that matters rather than the SQL: a session
carries a tenant, a query without one **raises** instead of returning
everything, and the policy applies to the owner too — because the application
almost always connects as the owner, and "we have RLS" plus "our role is the
owner" is a very common way to have no RLS at all.

The other four surfaces are here because they are the ones that leak. Everybody
remembers the database.
"""
from __future__ import annotations

from dataclasses import dataclass, field

NO_TENANT_CONTEXT = "NO_TENANT_CONTEXT"
CROSS_TENANT_READ = "CROSS_TENANT_READ"
CROSS_TENANT_WRITE = "CROSS_TENANT_WRITE"
CACHE_KEY_UNSCOPED = "CACHE_KEY_UNSCOPED"
TOPIC_TENANT_MISSING = "TOPIC_TENANT_MISSING"
CONSUMER_TENANT_MISMATCH = "CONSUMER_TENANT_MISMATCH"
LOG_TENANT_MISSING = "LOG_TENANT_MISSING"
LOG_FOREIGN_ROW = "LOG_FOREIGN_ROW"
EXPORT_MULTI_TENANT = "EXPORT_MULTI_TENANT"
EXPORT_FILTER_LATE = "EXPORT_FILTER_LATE"
OBJECT_PREFIX_DENIED = "OBJECT_PREFIX_DENIED"
JOB_TENANT_MISSING = "JOB_TENANT_MISSING"
PROBE_MISSING = "PROBE_MISSING"
PROBE_DID_NOT_DENY = "PROBE_DID_NOT_DENY"


class IsolationBreach(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class Session:
    """A database session. ``tenant_id`` of None is the dangerous case."""

    principal: str
    tenant_id: str | None = None
    is_table_owner: bool = False
    cross_tenant_granted: bool = False


@dataclass
class Row:
    tenant_id: str
    id: str
    payload: dict


class Database:
    """Row-level security as a property of the store, not of the caller."""

    def __init__(self, force_for_owner: bool = True) -> None:
        self.rows: list[Row] = []
        self.force_for_owner = force_for_owner

    def insert(self, session: Session, row: Row) -> Row:
        self._require_tenant(session)
        if row.tenant_id != session.tenant_id and not session.cross_tenant_granted:
            raise IsolationBreach(CROSS_TENANT_WRITE, row.tenant_id)
        self.rows.append(row)
        return row

    def select(self, session: Session) -> list[Row]:
        self._require_tenant(session)
        if session.cross_tenant_granted:
            return list(self.rows)
        if session.is_table_owner and not self.force_for_owner:
            # The configuration this model exists to refuse: the owner sees
            # everything, and the application connects as the owner.
            return list(self.rows)
        return [r for r in self.rows if r.tenant_id == session.tenant_id]

    def get(self, session: Session, row_id: str) -> Row:
        for row in self.select(session):
            if row.id == row_id:
                return row
        # Not "not found by luck": the row may exist for another tenant, and
        # saying so would itself be a leak, so the code is the same either way.
        raise IsolationBreach(CROSS_TENANT_READ, row_id)

    def _require_tenant(self, session: Session) -> None:
        if session.tenant_id is None and not session.cross_tenant_granted:
            # Forgetting the predicate is an error, never a wider result set.
            raise IsolationBreach(NO_TENANT_CONTEXT, session.principal)


class Cache:
    def __init__(self) -> None:
        self.store: dict[str, object] = {}

    def key(self, tenant_id: str | None, *parts: str) -> str:
        if not tenant_id:
            raise IsolationBreach(CACHE_KEY_UNSCOPED, ":".join(parts))
        return ":".join((tenant_id,) + parts)

    def put(self, tenant_id: str | None, *parts: str, value: object) -> str:
        key = self.key(tenant_id, *parts)
        self.store[key] = value
        return key

    def get(self, tenant_id: str | None, *parts: str) -> object | None:
        return self.store.get(self.key(tenant_id, *parts))

    def put_negative(self, tenant_id: str | None, *parts: str) -> str:
        """'Not found' is a per-tenant fact, so the negative cache is scoped too."""
        return self.put(tenant_id, *parts, value="__MISSING__")


@dataclass(frozen=True)
class Message:
    topic: str
    tenant_id: str | None
    body: dict


class MessageBus:
    def __init__(self) -> None:
        self.published: list[Message] = []

    def publish(self, message: Message) -> Message:
        if not message.tenant_id:
            raise IsolationBreach(TOPIC_TENANT_MISSING, message.topic)
        self.published.append(message)
        return message

    def consume(self, message: Message, *, consumer_tenant: str) -> dict:
        """The check that makes the envelope worth anything."""
        if message.tenant_id != consumer_tenant:
            raise IsolationBreach(CONSUMER_TENANT_MISMATCH,
                                  f"{message.tenant_id} != {consumer_tenant}")
        return message.body


class Logger:
    def __init__(self) -> None:
        self.lines: list[dict] = []

    def log(self, *, tenant_id: str | None, message: str, rows: tuple[Row, ...] = ()) -> dict:
        if not tenant_id:
            raise IsolationBreach(LOG_TENANT_MISSING, message)
        for row in rows:
            if row.tenant_id != tenant_id:
                raise IsolationBreach(LOG_FOREIGN_ROW, row.id)
        entry = {"tenant_id": tenant_id, "message": message,
                 "rows": tuple(r.id for r in rows)}
        self.lines.append(entry)
        return entry


class Exporter:
    def __init__(self, database: Database) -> None:
        self.database = database

    def export(self, session: Session, *, tenants: tuple[str, ...],
               filter_in_query: bool = True) -> list[Row]:
        if len(set(tenants)) != 1:
            raise IsolationBreach(EXPORT_MULTI_TENANT, ",".join(sorted(set(tenants))))
        if not filter_in_query:
            # The shape that gets "optimised" into pagination later, at which
            # point the last page carries somebody else's rows.
            raise IsolationBreach(EXPORT_FILTER_LATE, tenants[0])
        rows = self.database.select(session)
        self.verify_row_count(rows, tenants[0])
        return rows

    def verify_row_count(self, rows: list[Row], tenant_id: str) -> int:
        foreign = [r.id for r in rows if r.tenant_id != tenant_id]
        if foreign:
            raise IsolationBreach(CROSS_TENANT_READ, ",".join(foreign))
        return len(rows)


class ObjectStore:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put(self, tenant_id: str, name: str, blob: bytes) -> str:
        path = f"{tenant_id}/{name}"
        self.objects[path] = blob
        return path

    def get(self, session: Session, path: str) -> bytes:
        prefix = f"{session.tenant_id}/"
        if not path.startswith(prefix) and not session.cross_tenant_granted:
            raise IsolationBreach(OBJECT_PREFIX_DENIED, path)
        return self.objects[path]


@dataclass
class Job:
    name: str
    tenant_id: str | None = None
    processed: list[str] = field(default_factory=list)


class JobRunner:
    def __init__(self, database: Database) -> None:
        self.database = database

    def run(self, job: Job) -> list[str]:
        if not job.tenant_id:
            raise IsolationBreach(JOB_TENANT_MISSING, job.name)
        session = Session(principal=f"job:{job.name}", tenant_id=job.tenant_id)
        job.processed = [r.id for r in self.database.select(session)]
        return job.processed


# -- the probes ------------------------------------------------------------
def _denies(fn, code: str) -> bool:
    try:
        fn()
        return False
    except IsolationBreach as exc:
        return exc.code == code


def build_world() -> dict:
    database = Database()
    a = Session(principal="svc", tenant_id="ten_a")
    b = Session(principal="svc", tenant_id="ten_b")
    database.insert(a, Row("ten_a", "row_a", {"amount_minor": 100}))
    database.insert(b, Row("ten_b", "row_b", {"amount_minor": 200}))
    store = ObjectStore()
    store.put("ten_a", "invoice.pdf", b"a")
    store.put("ten_b", "invoice.pdf", b"b")
    return {"database": database, "a": a, "b": b, "store": store}


def probe_rls_denies_other_tenant(world: dict) -> bool:
    return _denies(lambda: world["database"].get(world["a"], "row_b"), CROSS_TENANT_READ)


def probe_object_prefix_denies_other_tenant(world: dict) -> bool:
    return _denies(lambda: world["store"].get(world["a"], "ten_b/invoice.pdf"),
                   OBJECT_PREFIX_DENIED)


def probe_cache_key_collides(world: dict) -> bool:
    cache = Cache()
    cache.put("ten_a", "user", "u1", value="A")
    cache.put("ten_b", "user", "u1", value="B")
    # Same logical key, different tenants, different values: no collision.
    if cache.get("ten_a", "user", "u1") != "A" or cache.get("ten_b", "user", "u1") != "B":
        return False
    return _denies(lambda: cache.put(None, "user", "u1", value="X"), CACHE_KEY_UNSCOPED)


def probe_consumer_rejects_foreign_tenant(world: dict) -> bool:
    bus = MessageBus()
    message = bus.publish(Message(topic="payments", tenant_id="ten_a", body={"id": "p1"}))
    return _denies(lambda: bus.consume(message, consumer_tenant="ten_b"),
                   CONSUMER_TENANT_MISMATCH)


def probe_log_rejects_foreign_row(world: dict) -> bool:
    logger = Logger()
    foreign = Row("ten_b", "row_b", {})
    return _denies(lambda: logger.log(tenant_id="ten_a", message="failed", rows=(foreign,)),
                   LOG_FOREIGN_ROW)


def probe_export_scoped_to_one_tenant(world: dict) -> bool:
    exporter = Exporter(world["database"])
    return _denies(lambda: exporter.export(world["a"], tenants=("ten_a", "ten_b")),
                   EXPORT_MULTI_TENANT)


def probe_search_denies_other_tenant(world: dict) -> bool:
    # The search index is modelled as the database's own scoped select: a shared
    # index with a query-time filter is the application-side filter again.
    rows = world["database"].select(world["a"])
    return all(r.tenant_id == "ten_a" for r in rows) and len(rows) == 1


def probe_job_rejects_missing_tenant(world: dict) -> bool:
    runner = JobRunner(world["database"])
    return _denies(lambda: runner.run(Job(name="nightly")), JOB_TENANT_MISSING)


PROBES = {
    "probe_rls_denies_other_tenant": probe_rls_denies_other_tenant,
    "probe_object_prefix_denies_other_tenant": probe_object_prefix_denies_other_tenant,
    "probe_cache_key_collides": probe_cache_key_collides,
    "probe_consumer_rejects_foreign_tenant": probe_consumer_rejects_foreign_tenant,
    "probe_log_rejects_foreign_row": probe_log_rejects_foreign_row,
    "probe_export_scoped_to_one_tenant": probe_export_scoped_to_one_tenant,
    "probe_search_denies_other_tenant": probe_search_denies_other_tenant,
    "probe_job_rejects_missing_tenant": probe_job_rejects_missing_tenant,
}


def run_probes(model: dict) -> dict[str, bool]:
    """Run the probe every surface names. A surface with no probe is a failure."""
    results: dict[str, bool] = {}
    world = build_world()
    for surface in model["surfaces"]:
        name = surface["probe"]["id"]
        probe = PROBES.get(name)
        if probe is None:
            raise IsolationBreach(PROBE_MISSING, f"{surface['id']}:{name}")
        outcome = bool(probe(world))
        if not outcome:
            raise IsolationBreach(PROBE_DID_NOT_DENY, f"{surface['id']}:{name}")
        results[surface["id"]] = outcome
    return results
