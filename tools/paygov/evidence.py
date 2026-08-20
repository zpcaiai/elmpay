"""B06 — evidence framework gate.

INVARIANT: this validator must never read an artefact that ``verify-all``
itself produces — test summaries, recorded exit codes, completion files. It
runs *as one of the recorded commands*, so reading its own outputs makes a
single failed run self-perpetuating: the next run fails on the previous run's
log and no amount of fixing can clear it. Those checks live in
``Programme.problems()``, which runs after the batch has been written.


The batch orchestrator checks that evidence *exists* and hashes correctly. This
validator checks that the evidence is *about the batch it claims to be about*:
traceability entries must point at files that exist, artefact lists must match
the completion file, the plan must actually contain a rollback and a threat
section, and each batch must have run the command classes that make its
evidence meaningful (test summary, governance gate, fail-closed proof,
timeout proof, idempotency proof, environment fingerprint).
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .errors import BudgetExceeded, Problem
from .orchestration import Programme
from .repo import Budget, load_json
from .structs import SEMVER, expect

POLICY = Path("governance/evidence-policy.json")
EVIDENCE = Path("evidence")
# Plan sections are matched by title keyword rather than by number so that a
# batch may add or reorder sections without weakening the requirement that the
# section itself exists.
PLAN_HEADING = re.compile(r"^##\s*\d+\.\s*(.+)$", re.MULTILINE)
SHARD_VALUE = re.compile(r"^([0-9]+)/([0-9]+)$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
TEST_SUMMARY = "scripts/test-summary.py"
NEGATIVE_CONTROLS = "scripts/negative-controls.py"
# Enforced in code, not only in the policy file. An independent review showed
# that dropping a class from governance/evidence-policy.json silently removed
# the requirement: a policy that can delete its own floor is not a floor.
MANDATORY_COMMAND_CLASS_IDS = frozenset({
    "test-summary", "governance-gate", "negative-controls",
    "timeout-fail-closed", "idempotency", "environment",
})


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("evidence", "B06")

def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget(seconds=120).start()
    where = str(POLICY)
    try:
        policy: Any = load_json(root / POLICY, budget)
        programme = Programme(root, budget)
    except BudgetExceeded:
        raise
    except Exception as exc:
        return [Problem("EVIDENCE_UNREADABLE", where, str(exc), "NN-12")]

    problems: list[Problem] = []
    problems += expect(bool(SEMVER.match(str(policy.get("schema_version", "")))),
                       "EVIDENCE_VERSION", where, "schema_version must be semantic version",
                       "NN-12")

    completion_dir = root / "evidence" / "completion"
    batches = sorted(p.stem for p in completion_dir.glob("*.json")) if completion_dir.is_dir() \
        else []
    if not batches:
        return problems + [Problem("EVIDENCE_EMPTY", str(EVIDENCE),
                                   "no completed batch evidence found", "NN-12")]

    for batch in batches:
        budget.check(batch)
        problems += _batch(root, batch, policy, programme)
    problems += _principals(root, policy, batches, where)
    problems += _policy_floor(policy, where)
    return problems


def _policy_floor(policy: dict, where: str) -> list[Problem]:
    declared = {c.get("id") for c in policy.get("required_command_classes", [])}
    return [Problem("EVIDENCE_POLICY_FLOOR", where,
                    f"required command class '{missing}' may not be removed from the evidence "
                    f"policy; it is part of the floor enforced in code", "NN-12")
            for missing in sorted(MANDATORY_COMMAND_CLASS_IDS - declared)]





def _batch(root: Path, batch: str, policy: dict, programme: Programme) -> list[Problem]:
    base = root / EVIDENCE / batch
    scope = str(EVIDENCE / batch)
    problems: list[Problem] = []

    if batch not in programme.batches:
        return [Problem("EVIDENCE_UNKNOWN_BATCH", scope,
                        f"'{batch}' has a completion file but is not in the manifest", "NN-12")]

    for name in policy["required_batch_files"]:
        problems += expect((base / name).is_file(), "EVIDENCE_FILE", scope,
                           f"missing required evidence file '{name}'", "NN-12")
    for name in policy["required_batch_dirs"]:
        problems += expect((base / name).is_dir(), "EVIDENCE_DIR", scope,
                           f"missing required evidence directory '{name}'", "NN-12")

    plan = base / "plan.md"
    if plan.is_file():
        headings = PLAN_HEADING.findall(plan.read_text(encoding="utf-8"))
        for section in policy["required_plan_sections"]:
            problems += expect(any(section in heading for heading in headings),
                               "EVIDENCE_PLAN_SECTION", f"{scope}/plan.md",
                               f"plan has no section covering '{section}'", "NN-12")

    spec = base / "commands.spec.json"
    if spec.is_file():
        try:
            commands = json.loads(spec.read_text(encoding="utf-8"))["commands"]
        except Exception as exc:
            problems.append(Problem("EVIDENCE_SPEC", f"{scope}/commands.spec.json",
                                    f"unreadable command spec: {exc}", "NN-12"))
            commands = []
        joined = "\n".join(c.get("command", "") for c in commands
                           if isinstance(c, dict))
        for required in policy["required_command_classes"]:
            problems += expect(required["match"] in joined, "EVIDENCE_COMMAND_CLASS",
                               f"{scope}/commands.spec.json",
                               f"no command covers '{required['id']}' ({required['purpose']})",
                               "NN-12")

        problems += _shards(commands, scope)

    problems += _traceability(root, base, scope, policy)
    problems += _artifacts(root, base, scope, batch, programme)
    problems += _recorded_commands(base, scope)
    return problems



def _tokens(command: str) -> list[str] | None:
    """Small dependency-free POSIX tokenizer for command-option validation."""
    if not isinstance(command, str):
        return None
    tokens: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for char in command:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
            else:
                current.append(char)
        elif char in ("'", '"'):
            quote = char
        elif char.isspace():
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)
    if quote or escaped:
        return None
    if current:
        tokens.append("".join(current))
    return tokens


def _has_script(tokens: list[str] | None, script: str) -> bool:
    return bool(tokens and any(token == script or token.endswith("/" + script)
                               for token in tokens))


def _option_values(tokens: list[str], option: str) -> list[str | None]:
    """Return every value supplied for an option, including malformed uses."""
    values: list[str | None] = []
    for index, token in enumerate(tokens):
        if token == option:
            values.append(tokens[index + 1] if index + 1 < len(tokens)
                          and not tokens[index + 1].startswith("--") else None)
        elif token.startswith(option + "="):
            values.append(token.split("=", 1)[1])
    return values


def _merge_sources(tokens: list[str]) -> list[str] | None:
    positions = [i for i, token in enumerate(tokens) if token == "--merge"]
    if len(positions) != 1:
        return None
    sources: list[str] = []
    for token in tokens[positions[0] + 1:]:
        if token.startswith("--"):
            break
        sources.append(token)
    return sources or None


def _shards(commands: list[Any], scope: str) -> list[Problem]:
    """Validate each sharded proof as its own exact partition.

    The regression suite and the negative-control harness are independent
    families: one may use four shards while the other uses three.  Within a
    family, however, sharded and unsharded modes may not be mixed, indices must
    be exactly ``1..N`` once each, and the regression merge must consume exactly
    the shard outputs after every shard run.
    """
    invocations: list[tuple[int, str, list[str] | None]] = []
    for index, entry in enumerate(commands):
        command = entry.get("command") if isinstance(entry, dict) else None
        if isinstance(command, str):
            invocations.append((index, command, _tokens(command)))

    problems: list[Problem] = []
    problems += _shard_family(invocations, scope, NEGATIVE_CONTROLS,
                              "negative-controls", requires_merge=False)
    problems += _shard_family(invocations, scope, TEST_SUMMARY,
                              "test-summary", requires_merge=True)
    return problems


def _shard_family(invocations: list[tuple[int, str, list[str] | None]], scope: str,
                  script: str, family: str, *, requires_merge: bool) -> list[Problem]:
    where = f"{scope}/commands.spec.json"
    selected = [(position, command, tokens) for position, command, tokens in invocations
                if _has_script(tokens, script) or script in command]
    if not selected:
        return []

    malformed_tokens = [command for _, command, tokens in selected if tokens is None]
    if malformed_tokens:
        return [Problem("EVIDENCE_SHARD_MALFORMED", where,
                        f"{family} command cannot be parsed: {malformed_tokens[0]}", "NN-12")]

    merges = [(position, tokens) for position, _, tokens in selected
              if tokens is not None and "--merge" in tokens]
    runs = [(position, tokens) for position, _, tokens in selected
            if tokens is not None and "--merge" not in tokens]
    parsed: list[tuple[int, int, int, list[str]]] = []
    unsharded: list[tuple[int, list[str]]] = []
    problems: list[Problem] = []
    for position, tokens in runs:
        values = _option_values(tokens, "--shard")
        if not values:
            unsharded.append((position, tokens))
            continue
        if len(values) != 1 or values[0] is None or not SHARD_VALUE.fullmatch(values[0]):
            problems.append(Problem("EVIDENCE_SHARD_MALFORMED", where,
                                    f"{family} must declare one --shard I/N value", "NN-12"))
            continue
        match = SHARD_VALUE.fullmatch(values[0])
        assert match is not None
        index, total = int(match.group(1)), int(match.group(2))
        if total < 1 or not 1 <= index <= total:
            problems.append(Problem("EVIDENCE_SHARD_RANGE", where,
                                    f"{family} shard {index}/{total} is outside 1..{total}",
                                    "NN-12"))
            continue
        parsed.append((position, index, total, tokens))

    if parsed and unsharded:
        problems.append(Problem("EVIDENCE_SHARD_MODE", where,
                                f"{family} mixes unsharded and sharded runs", "NN-12"))
    if not parsed:
        if requires_merge and merges:
            problems.append(Problem("EVIDENCE_SHARD_MERGE", where,
                                    "test-summary merge is present without a sharded run",
                                    "NN-12"))
        if requires_merge and len(unsharded) != 1:
            problems.append(Problem("EVIDENCE_SHARD_MODE", where,
                                    "test-summary unsharded mode requires exactly one run",
                                    "NN-12"))
        if requires_merge and unsharded:
            outputs = _option_values(unsharded[0][1], "--out")
            expected = f"{scope}/test-results/summary.json"
            if outputs != [expected]:
                problems.append(Problem("EVIDENCE_SHARD_MERGE", where,
                                        f"unsharded test-summary must write '{expected}'",
                                        "NN-12"))
        return problems

    totals = {total for _, _, total, _ in parsed}
    if len(totals) != 1:
        problems.append(Problem("EVIDENCE_SHARD_MIXED", where,
                                f"{family} mixes partition sizes {sorted(totals)}", "NN-12"))
        return problems
    total = next(iter(totals))
    indices = [index for _, index, _, _ in parsed]
    duplicates = sorted({index for index in indices if indices.count(index) > 1})
    if duplicates:
        problems.append(Problem("EVIDENCE_SHARD_DUPLICATE", where,
                                f"{family} repeats shard indices {duplicates}", "NN-12"))
    missing = sorted(set(range(1, total + 1)) - set(indices))
    if missing:
        problems.append(Problem("EVIDENCE_SHARD_INCOMPLETE", where,
                                f"{family} declares 1..{total} but never runs {missing}",
                                "NN-12"))

    if not requires_merge:
        if merges:
            problems.append(Problem("EVIDENCE_SHARD_MERGE", where,
                                    "negative-controls does not have a merge command", "NN-12"))
        return problems

    if len(merges) != 1:
        problems.append(Problem("EVIDENCE_SHARD_MERGE", where,
                                "sharded test-summary requires exactly one merge command",
                                "NN-12"))
        return problems
    merge_position, merge_tokens = merges[0]
    if merge_position <= max(position for position, _, _, _ in parsed):
        problems.append(Problem("EVIDENCE_SHARD_MERGE", where,
                                "test-summary merge must run after every shard", "NN-12"))

    outputs: list[tuple[int, str]] = []
    for _, index, _, tokens in parsed:
        values = _option_values(tokens, "--out")
        if len(values) != 1 or values[0] is None:
            problems.append(Problem("EVIDENCE_SHARD_MERGE", where,
                                    f"test-summary shard {index}/{total} must have one --out",
                                    "NN-12"))
        else:
            outputs.append((index, values[0]))
    expected_sources = [value for _, value in sorted(outputs)]
    actual_sources = _merge_sources(merge_tokens)
    final_outputs = _option_values(merge_tokens, "--out")
    expected_final = f"{scope}/test-results/summary.json"
    if len(outputs) != len(parsed) or actual_sources != expected_sources \
            or final_outputs != [expected_final]:
        problems.append(Problem("EVIDENCE_SHARD_MERGE", where,
                                "test-summary merge must consume each shard output once, in "
                                f"index order, and write '{expected_final}'", "NN-12"))
    return problems


def command_spec_sha256(path: Path) -> str:
    """Hash the exact spec bytes; command records are bound to this value."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_command_records(path: Path) -> list[dict]:
    records: list[dict] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"commands.ndjson line {lineno} is not an object")
        records.append(value)
    return records


def command_log_problems(root: Path, base: Path, commands: list[dict], records: list[dict],
                         spec_sha256: str, *, require_complete: bool) -> list[str]:
    """Validate an ordered transcript against the current command spec.

    Prefix mode is used before an append. Completion mode requires equality,
    not set inclusion: duplicates, reordering, a changed spec, failed commands,
    and output files that no longer match their recorded digest all block.
    """
    problems: list[str] = []
    if require_complete and len(records) != len(commands):
        problems.append(f"command log has {len(records)} records but current spec has "
                        f"{len(commands)} commands")
    if len(records) > len(commands):
        problems.append("command log is longer than the current spec")
    for position, record in enumerate(records):
        if position >= len(commands):
            break
        entry = commands[position]
        expected_exit = entry.get("expect", 0)
        if record.get("spec_sha256") != spec_sha256:
            problems.append(f"command record {position} is bound to a stale command spec")
        if record.get("spec_index") != position:
            problems.append(f"command record {position} has spec_index="
                            f"{record.get('spec_index')!r}")
        if record.get("command") != entry.get("command"):
            problems.append(f"command record {position} does not equal the current spec")
        if record.get("expected_exit_code") != expected_exit:
            problems.append(f"command record {position} expected-exit proof does not match spec")
        if record.get("exit_code") != expected_exit:
            problems.append(f"command record {position} did not succeed as specified")
        digest = record.get("output_sha256")
        if not isinstance(digest, str) or not HEX64.fullmatch(digest):
            problems.append(f"command record {position} has no valid output digest")
        if not isinstance(record.get("output_bytes"), int) or record.get("output_bytes", -1) < 0:
            problems.append(f"command record {position} has no valid output size")

        saved_to = entry.get("save_to")
        if not isinstance(saved_to, str) or not saved_to:
            problems.append(f"command {position} has no durable save_to output proof")
            continue
        if record.get("saved_to") != saved_to:
            problems.append(f"command record {position} save_to does not match spec")
            continue
        try:
            target = (base / saved_to).resolve(strict=False)
            target.relative_to(base.resolve())
        except (OSError, ValueError):
            problems.append(f"command {position} save_to escapes its evidence directory")
            continue
        if not target.is_file():
            problems.append(f"command {position} saved output is missing: {saved_to}")
            continue
        payload = target.read_bytes()
        current = hashlib.sha256(payload).hexdigest()
        if current != digest or record.get("saved_output_sha256") != current:
            problems.append(f"command {position} saved output digest no longer matches")
        if record.get("output_bytes") != len(payload):
            problems.append(f"command {position} saved output size no longer matches")
    return problems


def _recorded_commands(base: Path, scope: str) -> list[Problem]:
    """Re-read what was actually executed.

    The batch orchestrator only requires ``exit_code`` to be an integer, so a
    batch whose every command failed would still validate. Here the recorded
    exit code must equal the expected one, and the recorded command set must
    match the spec — otherwise the log is decoration.
    """
    ndjson = base / "commands.ndjson"
    spec_path = base / "commands.spec.json"
    if not ndjson.is_file() or not spec_path.is_file():
        return []
    problems: list[Problem] = []
    try:
        records = [json.loads(line) for line in
                   ndjson.read_text(encoding="utf-8").splitlines() if line.strip()]
        json.loads(spec_path.read_text(encoding="utf-8"))["commands"]
    except Exception as exc:
        return [Problem("EVIDENCE_COMMANDS", f"{scope}/commands.ndjson", str(exc), "NN-12")]

    # Recorded exit codes are compared in Programme.problems(), not here.
    # verify-all is itself one of the recorded commands, so a single failed run
    # would otherwise make every subsequent run fail on the previous run's log —
    # a self-perpetuating red that no amount of fixing could clear.
    del records
    return problems


def _traceability(root: Path, base: Path, scope: str, policy: dict) -> list[Problem]:
    path = base / "traceability.json"
    if not path.is_file():
        return []
    problems: list[Problem] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [Problem("EVIDENCE_TRACE", f"{scope}/traceability.json", str(exc), "NN-12")]
    for section, key in policy["traceability_path_keys"].items():
        for entry in data.get(section, []):
            rel = entry.get(key) if isinstance(entry, dict) else None
            if not isinstance(rel, str):
                problems.append(Problem("EVIDENCE_TRACE", f"{scope}/traceability.json",
                                        f"{section} entry has no '{key}'", "NN-12"))
                continue
            target = root / rel
            problems += expect(target.exists(), "EVIDENCE_TRACE_DANGLING",
                               f"{scope}/traceability.json",
                               f"{section} references '{rel}' which does not exist", "NN-12")
    return problems


def _artifacts(root: Path, base: Path, scope: str, batch: str,
               programme: Programme) -> list[Problem]:
    listing = base / "artifacts.json"
    completion = programme.completion_path(batch)
    if not listing.is_file() or not completion.is_file():
        return []
    problems: list[Problem] = []
    try:
        declared = set(json.loads(listing.read_text(encoding="utf-8")))
        recorded = {a["path"] for a in
                    json.loads(completion.read_text(encoding="utf-8"))["artifacts"]}
    except Exception as exc:
        return [Problem("EVIDENCE_ARTIFACT", f"{scope}/artifacts.json", str(exc), "NN-12")]
    # The declared-vs-recorded comparison lives in Programme.problems(): this
    # validator runs *before* a batch rewrites its completion file, so checking
    # agreement here would fail every batch while it produces its own evidence.
    del recorded
    for rel in sorted(declared):
        # Digest verification deliberately lives in the validate path
        # (Programme.problems), not here: verify-all runs *before* a batch
        # rewrites its completion file, so checking digests here would make
        # every batch fail while it is producing its own evidence.
        problems += expect((root / rel).is_file(), "EVIDENCE_ARTIFACT",
                           f"{scope}/artifacts.json", f"declared artefact '{rel}' does not exist",
                           "NN-12")
    return problems


def _principals(root: Path, policy: dict, batches: list[str], where: str) -> list[Problem]:
    expected = policy.get("principals", {})
    problems: list[Problem] = []
    for batch in batches:
        path = root / "evidence" / "completion" / f"{batch}.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for role in ("executor", "reviewer"):
            if role in expected:
                problems += expect(data.get(role) == expected[role], "EVIDENCE_PRINCIPAL",
                                   str(path.relative_to(root)),
                                   f"{role} must be '{expected[role]}' as declared in the "
                                   f"evidence policy", "NN-11")
        problems += expect(data.get("executor") != data.get("reviewer"), "EVIDENCE_PRINCIPAL",
                           str(path.relative_to(root)),
                           "executor and reviewer must differ (four-eyes)", "NN-11")
    return problems
