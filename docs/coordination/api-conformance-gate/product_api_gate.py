#!/usr/bin/env python3
"""Black-box conformance gate for AGNT product/API contracts.

Validates live HTTP responses or a capture manifest against:
  - agnt.history.v1
  - agnt.timeline.v1
  - agnt.execution-status.v1

Standard-library only. This module never mutates the target API.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from urllib.request import Request, urlopen

HISTORY_VERSION = "agnt.history.v1"
TIMELINE_VERSION = "agnt.timeline.v1"
EXECUTION_VERSION = "agnt.execution-status.v1"
MISSION_STATUSES = {"en_file", "en_cours", "termine", "refuse", "erreur", "inconnu"}
APPLICABILITY = {"applicable", "non_applicable", "inconnu"}
SELECTION = {"selectionne", "non_selectionne", "inconnu"}
CONDITION = {"remplie", "bloquee", "inconnu"}
AUTHORIZATION = {"autorise", "non_autorise", "non_evalue", "inconnu"}
AVAILABILITY = {"disponible", "indisponible", "inconnu"}
EXECUTION = {"non_lance", "en_cours", "termine", "echoue", "timed_out", "cancelled", "unavailable", "inconnu"}
DETECTION = {"findings_presents", "rien_trouve", "non_evalue", "inconnu"}
PROOFS = {"recorded", "derived", "provider_reported", "unknown"}
COMPLETENESS = {"complete", "partial", "unavailable", "conflict"}
TIMELINE_STATES = {"complete", "partial", "unavailable"}
EVENT_DATA_STATES = {"complete", "partial", "redacted", "unavailable"}
EVENT_VISIBILITY = {"summary", "mission", "technical"}
EVENT_CONSEQUENCES = {"recorded", "started", "progress", "completed", "succeeded", "refused", "failed", "skipped", "unavailable", "unknown"}
EVENT_CATEGORIES = {"mission", "intent", "plan", "policy", "execution", "coverage", "correlation", "report", "security", "system", "unknown"}
MISSING_ARTIFACTS = {"run", "plan", "intent", "findings", "clusters", "report", "coverage", "events"}
PROVENANCE_KEYS = {"provider_id", "provider_kind", "transport", "server_id", "tool_id", "protocol", "confidence", "availability", "request_id", "correlation_id"}
FORBIDDEN_KEYS = {
    "endpoint", "server_url", "socket", "headers", "authorization_header",
    "cookie", "set_cookie", "token", "access_token", "refresh_token", "credential",
    "credentials", "password", "passwd", "private_key", "argv", "command", "environment",
    "env", "stack", "stack_trace", "traceback", "raw_request", "raw_response", "raw_payload",
    "raw_output", "stderr", "absolute_path", "storage_path",
}
FAKE_MARKERS = ("never serve as product data", "mode démonstration", "demo data", "maquette")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
MISSION_ID = re.compile(r"^m-[A-Za-z0-9-]+$")
REASON = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
MARKUP = re.compile(r"<\s*(?:script|img|iframe|object|embed|a)\b", re.I)
BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]+", re.I)
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
ABSOLUTE_PATH = re.compile(r"(?:^|[\s'\"])(?:/(?:home|Users|root|var|tmp|etc)/|[A-Za-z]:\\)")
CONTRACT_DIR = Path(__file__).resolve().parent.parent


@dataclass
class Response:
    path: str
    status: int
    body: Any
    role: str = ""


class Report:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.passes: list[str] = []
        self.failures: list[str] = []
        self.skips: list[str] = []
        self.coverage: set[str] = set()

    def check(self, condition: bool, label: str, detail: str = "") -> bool:
        if condition:
            self.passes.append(label)
            if self.verbose:
                print(f"PASS  {label}")
            return True
        text = label + (f" — {detail}" if detail else "")
        self.failures.append(text)
        print(f"FAIL  {text}", file=sys.stderr)
        return False

    def fail(self, label: str, detail: str = "") -> None:
        self.check(False, label, detail)

    def skip(self, label: str, detail: str = "") -> None:
        text = label + (f" — {detail}" if detail else "")
        self.skips.append(text)
        if self.verbose:
            print(f"SKIP  {text}")

    def summary(self) -> None:
        print(f"\nAGNT PRODUCT API GATE: {len(self.passes)} PASS · {len(self.failures)} FAIL · {len(self.skips)} SKIP")
        if self.failures:
            print("Violations:")
            for failure in self.failures:
                print(f"- {failure}")
        if self.skips:
            print("Coverage not exercised:")
            for skipped in self.skips:
                print(f"- {skipped}")


def check_contract_files(report: Report) -> None:
    """Fail closed if the executable assertions drift from the three versioned schemas."""
    try:
        history = json.loads((CONTRACT_DIR / "mission-history-v1.schema.json").read_text(encoding="utf-8"))
        timeline = json.loads((CONTRACT_DIR / "mission-timeline-v1.schema.json").read_text(encoding="utf-8"))
        execution = json.loads((CONTRACT_DIR / "execution-status-v1.schema.json").read_text(encoding="utf-8"))
        report.check(history["$defs"]["detailResponse"]["properties"]["schema_version"]["const"] == HISTORY_VERSION,
                     "gate: history schema version alignment")
        report.check(set(history["$defs"]["status"]["enum"]) == MISSION_STATUSES,
                     "gate: Mission status vocabulary alignment")
        event = timeline["$defs"]["event"]["properties"]
        report.check(timeline["properties"]["schema_version"]["const"] == TIMELINE_VERSION,
                     "gate: timeline schema version alignment")
        report.check(set(event["category"]["enum"]) == EVENT_CATEGORIES and
                     set(event["consequence"]["enum"]) == EVENT_CONSEQUENCES and
                     set(event["visibility"]["enum"]) == EVENT_VISIBILITY and
                     set(event["data_state"]["enum"]) == EVENT_DATA_STATES,
                     "gate: timeline vocabularies alignment")
        defs = execution["$defs"]
        enum = lambda name: set(defs[name]["allOf"][1]["properties"]["value"]["enum"])
        report.check(execution["properties"]["schema_version"]["const"] == EXECUTION_VERSION,
                     "gate: execution schema version alignment")
        report.check(enum("applicability") == APPLICABILITY and enum("selection") == SELECTION and
                     enum("condition") == CONDITION and enum("authorization") == AUTHORIZATION and
                     set(defs["availability"]["properties"]["value"]["enum"]) == AVAILABILITY and
                     set(defs["execution"]["properties"]["value"]["enum"]) == EXECUTION and
                     set(defs["detection"]["properties"]["value"]["enum"]) == DETECTION,
                     "gate: execution vocabularies alignment")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        report.fail("gate: local contract schemas readable", str(error))


def is_dict(value: Any) -> bool:
    return isinstance(value, dict)


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def walk(value: Any, path: str = "$"):
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{path}[{index}]")


def check_safe_payload(report: Report, body: Any, context: str, allow_fixtures: bool) -> None:
    for path, value in walk(body):
        if isinstance(value, dict):
            for key in value:
                normalized = str(key).lower().replace("-", "_")
                if normalized == "$fixture":
                    report.check(allow_fixtures, f"{context}: fixture marker allowed only in fixture mode", path)
                if normalized in FORBIDDEN_KEYS or normalized.startswith("raw_"):
                    report.fail(f"{context}: forbidden field", f"{path}.{key}")
        if not isinstance(value, str):
            continue
        lower = value.lower()
        if not allow_fixtures and any(marker in lower for marker in FAKE_MARKERS):
            report.fail(f"{context}: demo/fixture data exposed by API", path)
        if BEARER.search(value) or PRIVATE_KEY.search(value) or JWT.search(value):
            report.fail(f"{context}: credential-like value exposed", path)
        if ABSOLUTE_PATH.search(value):
            report.fail(f"{context}: absolute local path exposed", path)
        if MARKUP.search(value):
            report.fail(f"{context}: active markup exposed", path)
        if re.match(r"^https?://", value):
            parsed = urlsplit(value)
            if parsed.username is not None or parsed.password is not None:
                report.fail(f"{context}: URL userinfo exposed", path)
            sensitive_query = {"token", "key", "api_key", "password", "secret", "auth"}
            if sensitive_query & {k.lower() for k in parse_qs(parsed.query)}:
                report.fail(f"{context}: sensitive URL query exposed", path)


def validate_summary(report: Report, item: Any, context: str) -> None:
    if not report.check(is_dict(item), f"{context}: summary is an object"):
        return
    required = {"mission_id", "detail_href", "request", "target", "status", "created_at", "updated_at", "artifacts"}
    report.check(required <= set(item), f"{context}: required summary fields", str(sorted(required - set(item))))
    mid = item.get("mission_id")
    report.check(isinstance(mid, str) and bool(MISSION_ID.fullmatch(mid)), f"{context}: persistent mission_id", repr(mid))
    report.check(item.get("detail_href") == f"/api/missions/{mid}", f"{context}: detail_href matches mission_id")
    report.check(item.get("status") in MISSION_STATUSES, f"{context}: canonical Mission status", repr(item.get("status")))
    report.check("submission_id" not in item and item.get("id") != mid, f"{context}: no submission ID masquerades as mission ID")
    request = item.get("request")
    report.check(is_dict(request) and isinstance(request.get("title"), str) and 0 < len(request["title"]) <= 240,
                 f"{context}: safe bounded request title")
    target = item.get("target")
    report.check(is_dict(target) and isinstance(target.get("type"), str) and isinstance(target.get("display_name"), str),
                 f"{context}: safe target projection")
    report.check(parse_time(item.get("created_at")) is not None and parse_time(item.get("updated_at")) is not None,
                 f"{context}: RFC3339 dates")
    artifacts = item.get("artifacts")
    report.check(is_dict(artifacts) and {"detail", "findings", "clusters", "report"} <= set(artifacts)
                 and all(isinstance(artifacts[k], bool) for k in ("detail", "findings", "clusters", "report")),
                 f"{context}: factual artifact availability")
    findings = item.get("findings_summary")
    if findings is not None:
        valid = is_dict(findings) and isinstance(findings.get("total"), int) and findings["total"] >= 0 and is_dict(findings.get("by_severity"))
        report.check(valid, f"{context}: findings summary shape")
        if valid:
            counts = list(findings["by_severity"].values())
            report.check(all(isinstance(n, int) and n >= 0 for n in counts) and sum(counts) == findings["total"],
                         f"{context}: severity counts equal total")
            report.check(bool(artifacts and artifacts.get("findings")), f"{context}: findings count backed by artifact")


def validate_list(report: Report, response: Response, allow_fixtures: bool) -> list[dict]:
    context = f"{response.role or 'list'} {response.path}"
    report.check(response.status == 200, f"{context}: HTTP 200", str(response.status))
    check_safe_payload(report, response.body, context, allow_fixtures)
    body = response.body
    if not report.check(is_dict(body), f"{context}: JSON object"):
        return []
    report.check(body.get("schema_version") == HISTORY_VERSION, f"{context}: history schema version")
    items = body.get("items")
    if not report.check(isinstance(items, list), f"{context}: items array"):
        return []
    page = body.get("page")
    page_ok = is_dict(page) and isinstance(page.get("limit"), int) and 1 <= page["limit"] <= 100 and (page.get("next_cursor") is None or isinstance(page.get("next_cursor"), str))
    report.check(page_ok, f"{context}: pagination envelope")
    for index, item in enumerate(items):
        validate_summary(report, item, f"{context}.items[{index}]")
    ordering = [(parse_time(item.get("created_at")), item.get("mission_id")) for item in items if is_dict(item)]
    if all(date is not None and isinstance(mid, str) for date, mid in ordering):
        report.check(ordering == sorted(ordering, reverse=True), f"{context}: stable descending order")
    mids = [item.get("mission_id") for item in items if is_dict(item)]
    report.check(len(mids) == len(set(mids)), f"{context}: unique mission IDs")
    query = parse_qs(urlsplit(response.path).query)
    if "limit" in query:
        try:
            requested = int(query["limit"][-1])
            report.check(len(items) <= requested, f"{context}: requested limit respected")
            if page_ok:
                report.check(page["limit"] == requested, f"{context}: page limit echoes request")
        except ValueError:
            report.fail(f"{context}: gate request limit parse")
    if "status" in query:
        expected = query["status"][-1]
        report.check(all(is_dict(item) and item.get("status") == expected for item in items), f"{context}: status filter respected")
    if "target_type" in query:
        expected = query["target_type"][-1]
        report.check(all(is_dict(item) and is_dict(item.get("target")) and item["target"].get("type") == expected for item in items), f"{context}: target filter respected")
    if response.role == "empty_list" or not items:
        report.coverage.add("empty_list")
        report.check(response.status == 200 and items == [], f"{context}: real empty list is HTTP 200 + items []")
    report.coverage.add("list")
    return items


def validate_timeline(report: Report, timeline: Any, mission_id: str, context: str) -> None:
    if not report.check(is_dict(timeline), f"{context}: timeline object"):
        return
    report.check(timeline.get("schema_version") == TIMELINE_VERSION, f"{context}: timeline schema version")
    report.check(timeline.get("state") in TIMELINE_STATES, f"{context}: timeline state")
    report.check(timeline.get("ordering") == "journal_sequence_ascending", f"{context}: sequence ordering declared")
    events = timeline.get("events")
    if not report.check(isinstance(events, list), f"{context}: events array"):
        return
    report.check(timeline.get("returned_events") == len(events), f"{context}: returned_events is factual")
    truncated = timeline.get("truncated")
    next_cursor = timeline.get("next_cursor")
    report.check(isinstance(truncated, bool) and (truncated == (next_cursor is not None)), f"{context}: truncation/cursor consistency")
    sequences: list[int] = []
    positions: list[int] = []
    event_ids: list[str] = []
    for index, event in enumerate(events):
        ectx = f"{context}.events[{index}]"
        if not report.check(is_dict(event), f"{ectx}: event object"):
            continue
        source = event.get("source") or {}
        sequence = source.get("sequence")
        valid_sequence = isinstance(sequence, int) and sequence > 0
        report.check(source.get("kind") == "journal" and valid_sequence, f"{ectx}: journal sequence")
        if valid_sequence:
            sequences.append(sequence)
            report.check(event.get("event_id") == f"{mission_id}:{sequence}", f"{ectx}: deterministic event ID")
        event_ids.append(event.get("event_id"))
        position = event.get("position")
        report.check(isinstance(position, int) and position > 0, f"{ectx}: stable positive position")
        if isinstance(position, int) and position > 0:
            positions.append(position)
        report.check((event.get("references") or {}).get("mission_id") == mission_id, f"{ectx}: Mission reference")
        report.check(event.get("category") in EVENT_CATEGORIES, f"{ectx}: category enum")
        report.check(event.get("consequence") in EVENT_CONSEQUENCES, f"{ectx}: consequence enum")
        report.check(event.get("visibility") in EVENT_VISIBILITY, f"{ectx}: visibility enum")
        report.check(event.get("data_state") in EVENT_DATA_STATES, f"{ectx}: data state enum")
        summary = event.get("safe_summary")
        report.check(isinstance(summary, str) and 0 < len(summary) <= 240 and "\n" not in summary, f"{ectx}: bounded safe summary")
        time = event.get("time")
        time_ok = is_dict(time) and (time.get("state") in {"unavailable", "redacted"} and "timestamp" not in time or time.get("state") == "recorded" and parse_time(time.get("timestamp")) is not None)
        report.check(time_ok, f"{ectx}: explicit real/absent timestamp")
        provenance = event.get("provenance")
        if provenance is not None:
            validate_provenance(report, provenance, f"{ectx}.provenance")
        if event.get("category") == "unknown":
            report.coverage.add("unknown")
            report.check(event.get("kind") == "unknown_event_recorded" and event.get("data_state") == "unavailable", f"{ectx}: unknown event handled safely")
    report.check(sequences == sorted(sequences) and len(sequences) == len(set(sequences)), f"{context}: strictly ordered unique sequences")
    report.check(positions == sorted(positions) and len(positions) == len(set(positions)), f"{context}: strictly ordered unique positions")
    report.check(len(event_ids) == len(set(event_ids)), f"{context}: no timeline event duplication")
    report.coverage.add("timeline")


def validate_provenance(report: Report, provenance: Any, context: str) -> None:
    if not report.check(is_dict(provenance), f"{context}: provenance object"):
        return
    report.check(set(provenance) <= PROVENANCE_KEYS, f"{context}: allowlisted provenance keys", str(sorted(set(provenance) - PROVENANCE_KEYS)))
    if provenance.get("provider_kind") == "mcp":
        report.coverage.add("mcp")
    for key in ("provider_id", "server_id", "tool_id", "request_id", "correlation_id"):
        if key in provenance:
            report.check(isinstance(provenance[key], str) and bool(SAFE_ID.fullmatch(provenance[key])), f"{context}: safe {key}")
    if "provider_kind" in provenance:
        report.check(provenance["provider_kind"] in {"local", "mcp", "external"}, f"{context}: provider_kind enum")
    if "transport" in provenance:
        report.check(isinstance(provenance["transport"], str) and bool(re.fullmatch(r"[a-z0-9_.-]{1,40}", provenance["transport"])), f"{context}: safe transport")
    if "protocol" in provenance:
        protocol = provenance["protocol"]
        protocol_ok = is_dict(protocol) and set(protocol) <= {"name", "version"} and isinstance(protocol.get("name"), str) and bool(re.fullmatch(r"[a-z0-9_.-]{1,40}", protocol["name"]))
        if protocol_ok and "version" in protocol:
            protocol_ok = isinstance(protocol["version"], str) and bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", protocol["version"]))
        report.check(protocol_ok, f"{context}: safe protocol")
    if "availability" in provenance:
        report.check(provenance["availability"] in {"available", "degraded", "unavailable", "unknown"}, f"{context}: provenance availability enum")
    if "confidence" in provenance:
        confidence = provenance["confidence"]
        report.check(is_dict(confidence) and set(confidence) <= {"level", "basis"} and confidence.get("level") in {"low", "medium", "high", "unknown"} and confidence.get("basis") in {"provider_declared", "agnt_assessed", "corroborated", "unknown"}, f"{context}: confidence includes basis")


def dimension(report: Report, record: dict, name: str, values: set[str], context: str) -> str | None:
    value = record.get(name)
    ok = is_dict(value) and value.get("value") in values and value.get("proof") in PROOFS
    report.check(ok, f"{context}: {name} dimension")
    if ok and "reason_code" in value:
        report.check(isinstance(value["reason_code"], str) and bool(REASON.fullmatch(value["reason_code"])), f"{context}: safe {name} reason")
    return value.get("value") if is_dict(value) else None


def validate_execution(report: Report, record: Any, context: str) -> None:
    if not report.check(is_dict(record), f"{context}: execution object"):
        return
    report.check(record.get("schema_version") == EXECUTION_VERSION, f"{context}: execution status schema version")
    pid = record.get("provider_id")
    report.check(isinstance(pid, str) and bool(SAFE_ID.fullmatch(pid)), f"{context}: safe provider_id")
    app = dimension(report, record, "applicability", APPLICABILITY, context)
    sel = dimension(report, record, "selection", SELECTION, context)
    cond = dimension(report, record, "condition", CONDITION, context)
    auth = dimension(report, record, "authorization", AUTHORIZATION, context)
    avail = dimension(report, record, "availability", AVAILABILITY, context)
    exe = record.get("execution") or {}
    exe_ok = is_dict(exe) and exe.get("value") in EXECUTION and exe.get("invocation") in {"oui", "non", "inconnu"} and exe.get("output") in {"exploitable", "partiel", "non_exploitable", "inconnu"} and exe.get("proof") in PROOFS
    report.check(exe_ok, f"{context}: execution dimension")
    if "reason_code" in exe:
        report.check(isinstance(exe["reason_code"], str) and bool(REASON.fullmatch(exe["reason_code"])), f"{context}: safe execution reason")
    det = record.get("detection") or {}
    det_ok = is_dict(det) and det.get("value") in DETECTION and det.get("proof") in PROOFS
    report.check(det_ok, f"{context}: detection dimension")
    if "reason_code" in det:
        report.check(isinstance(det["reason_code"], str) and bool(REASON.fullmatch(det["reason_code"])), f"{context}: safe detection reason")
    comp = record.get("completeness") or {}
    comp_ok = is_dict(comp) and comp.get("state") in COMPLETENESS and isinstance(comp.get("missing"), list) and isinstance(comp.get("limitations"), list)
    report.check(comp_ok, f"{context}: completeness dimension")
    if comp_ok:
        report.check(all(isinstance(code, str) and bool(REASON.fullmatch(code)) for code in comp["missing"] + comp["limitations"]), f"{context}: safe completeness codes")
    if exe.get("value") == "termine":
        report.check(exe.get("invocation") == "oui" and exe.get("output") in {"exploitable", "partiel"}, f"{context}: completed execution has invocation/output proof")
    if exe.get("value") in {"non_lance", "unavailable"}:
        report.check(exe.get("invocation") == "non" and exe.get("output") == "non_exploitable", f"{context}: non-invoked execution has no output")
    detection = det.get("value")
    count = det.get("findings_count")
    if detection == "rien_trouve":
        report.coverage.add("zero")
        zero_ok = exe.get("value") == "termine" and exe.get("invocation") == "oui" and exe.get("output") == "exploitable" and count == 0 and isinstance(det.get("analyzed_targets"), int) and det["analyzed_targets"] > 0 and comp.get("state") == "complete"
        report.check(zero_ok, f"{context}: zero count has full rien_trouve proof")
    elif detection == "findings_presents":
        report.coverage.add("findings")
        report.check(isinstance(count, int) and count > 0 and exe.get("value") == "termine", f"{context}: findings have positive normalized count")
    else:
        report.check("findings_count" not in det, f"{context}: no count for unknown/non-evaluated detection")
    unsafe_zero_states = {"non_lance", "echoue", "timed_out", "cancelled", "unavailable", "inconnu"}
    if exe.get("value") in unsafe_zero_states or avail == "indisponible" or auth in {"non_autorise", "non_evalue"} or app == "non_applicable" or cond == "bloquee" or sel == "non_selectionne":
        report.check(detection != "rien_trouve" and count is None, f"{context}: absence/refusal/error cannot become zero")
    mapping = {"unavailable": "unavailable", "timed_out": "timeout", "cancelled": "cancelled", "echoue": "failed", "inconnu": "unknown"}
    if exe.get("value") in mapping:
        report.coverage.add(mapping[exe["value"]])
    if auth == "non_autorise":
        report.coverage.add("refused")
    if app == "non_applicable":
        report.coverage.add("non_applicable")
    if comp.get("state") in {"partial", "unavailable", "conflict"}:
        report.coverage.add("incomplete")
    provenance = record.get("provenance")
    if provenance is not None:
        validate_provenance(report, provenance, f"{context}.provenance")


def validate_detail(report: Report, response: Response, allow_fixtures: bool) -> None:
    context = f"{response.role or 'detail'} {response.path}"
    report.check(response.status == 200, f"{context}: HTTP 200", str(response.status))
    check_safe_payload(report, response.body, context, allow_fixtures)
    body = response.body
    if not report.check(is_dict(body), f"{context}: JSON object"):
        return
    report.check(body.get("schema_version") == HISTORY_VERSION, f"{context}: history schema version")
    mission = body.get("mission")
    validate_summary(report, mission, f"{context}.mission")
    mid = mission.get("mission_id") if is_dict(mission) else ""
    path_mid = urlsplit(response.path).path.rstrip("/").rsplit("/", 1)[-1]
    report.check(path_mid == mid, f"{context}: path mission ID matches body", f"{path_mid!r} != {mid!r}")
    data = body.get("data")
    if not report.check(is_dict(data), f"{context}: data object"):
        return
    missing = body.get("missing_artifacts")
    missing_ok = isinstance(missing, list) and len(missing) == len(set(missing)) and set(missing) <= MISSING_ARTIFACTS
    report.check(missing_ok, f"{context}: logical missing_artifacts only")
    if missing_ok:
        for artifact in missing:
            if artifact in {"findings", "clusters", "report", "coverage"}:
                report.check(artifact not in data, f"{context}: missing {artifact} is not fabricated in data")
        if "findings" in missing:
            report.check(not is_dict(mission) or "findings_summary" not in mission, f"{context}: missing findings has no zero/count summary")
    timeline = data.get("timeline")
    if timeline is None:
        report.fail(f"{context}: data.timeline required for three-contract gate")
    else:
        validate_timeline(report, timeline, mid, f"{context}.data.timeline")
    legacy = data.get("events")
    if legacy is not None:
        report.check(isinstance(legacy, list), f"{context}: legacy data.events remains independent")
        if is_dict(timeline):
            report.check(timeline.get("returned_events") == len(timeline.get("events") or []), f"{context}: legacy events are not merged into timeline counts")
    executions = data.get("executions")
    if executions is None:
        report.fail(f"{context}: data.executions required for three-contract gate")
    elif report.check(isinstance(executions, list), f"{context}: executions array"):
        for index, execution in enumerate(executions):
            validate_execution(report, execution, f"{context}.data.executions[{index}]")
    report.coverage.add("detail")


class LiveClient:
    def __init__(self, base_url: str, timeout: float):
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout

    def get(self, path: str, role: str = "") -> Response:
        url = urljoin(self.base_url, path.lstrip("/"))
        req = Request(url, headers={"Accept": "application/json", "User-Agent": "agnt-product-api-gate/1"})
        try:
            with urlopen(req, timeout=self.timeout) as response:
                raw = response.read()
                status = response.status
        except HTTPError as error:
            status = error.code
            raw = error.read()
        except (URLError, TimeoutError, OSError) as error:
            raise RuntimeError(f"GET {url}: {error}") from error
        try:
            body = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError(f"GET {url}: response is not valid UTF-8 JSON: {error}") from error
        return Response(path=path, status=status, body=body, role=role)


def load_capture(manifest_path: Path) -> tuple[list[Response], str | None]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not is_dict(manifest) or not isinstance(manifest.get("responses"), list):
        raise ValueError("capture manifest must contain a responses array")
    responses = []
    for index, entry in enumerate(manifest["responses"]):
        if not is_dict(entry) or not isinstance(entry.get("path"), str) or not isinstance(entry.get("status"), int):
            raise ValueError(f"capture response #{index} requires path and integer status")
        if "body_file" in entry:
            body_path = (manifest_path.parent / entry["body_file"]).resolve()
            if not body_path.is_relative_to(manifest_path.parent.resolve()):
                raise ValueError(f"capture body_file escapes manifest directory: {entry['body_file']}")
            body = json.loads(body_path.read_text(encoding="utf-8"))
        elif "body" in entry:
            body = entry["body"]
        else:
            raise ValueError(f"capture response #{index} requires body or body_file")
        responses.append(Response(entry["path"], entry["status"], body, str(entry.get("role") or "")))
    submission_id = manifest.get("submission_id")
    if submission_id is not None and not isinstance(submission_id, str):
        raise ValueError("submission_id must be a string")
    return responses, submission_id


def is_list_path(path: str) -> bool:
    return urlsplit(path).path.rstrip("/") == "/api/missions"


def is_detail_path(path: str) -> bool:
    parts = urlsplit(path).path.rstrip("/").split("/")
    return len(parts) == 4 and parts[:3] == ["", "api", "missions"]


def run_capture(report: Report, manifest: Path, allow_fixtures: bool) -> str | None:
    responses, submission_id = load_capture(manifest)
    list_responses = [r for r in responses if is_list_path(r.path) and r.status == 200]
    details = [r for r in responses if is_detail_path(r.path) and r.status == 200]
    report.check(bool(list_responses), "capture: at least one successful mission list response")
    all_items = []
    items_by_response: list[tuple[Response, list[dict]]] = []
    for response in list_responses:
        validated = validate_list(report, response, allow_fixtures)
        all_items.extend(validated)
        items_by_response.append((response, validated))
    base_ids = {item.get("mission_id") for response, values in items_by_response if response.role == "list" for item in values}
    for response, values in items_by_response:
        if response.role == "pagination_next":
            next_ids = {item.get("mission_id") for item in values}
            report.check(not (base_ids & next_ids), f"{response.role} {response.path}: cursor page has no duplicate missions")
            base_ids |= next_ids
    for response in details:
        validate_detail(report, response, allow_fixtures)
    has_nonempty_list = any(is_dict(r.body) and bool(r.body.get("items")) for r in list_responses)
    report.check(bool(details) or not has_nonempty_list, "capture: details exist unless history is empty")
    invalid_filters = [r for r in responses if r.role == "invalid_filter"]
    if invalid_filters:
        for response in invalid_filters:
            report.check(response.status == 400, f"{response.role} {response.path}: invalid filter rejected")
    else:
        report.skip("invalid filter rejection", "capture has no invalid_filter role")
    validate_submission_distinction(report, submission_id, all_items)
    return submission_id


def run_live(report: Report, base_url: str, timeout: float, max_details: int, submission_id: str | None, allow_fixtures: bool) -> None:
    client = LiveClient(base_url, timeout)
    primary = client.get("/api/missions?limit=25", "list")
    items = validate_list(report, primary, allow_fixtures)
    # Safe read-only probes for limit and filters.
    validate_list(report, client.get("/api/missions?limit=1", "pagination_probe"), allow_fixtures)
    first_item = next((item for item in items if is_dict(item)), None)
    if first_item:
        status = first_item.get("status")
        target_type = (first_item.get("target") or {}).get("type")
        if status in MISSION_STATUSES:
            validate_list(report, client.get("/api/missions?" + urlencode({"limit": 25, "status": status}), "status_filter"), allow_fixtures)
        if isinstance(target_type, str):
            validate_list(report, client.get("/api/missions?" + urlencode({"limit": 25, "target_type": target_type}), "target_filter"), allow_fixtures)
    else:
        report.skip("filtered non-empty semantics", "API currently has no missions")
    invalid = client.get("/api/missions?status=__agnt_invalid_status__", "invalid_filter")
    report.check(invalid.status == 400, "live API: invalid status filter returns HTTP 400", str(invalid.status))
    next_cursor = ((primary.body or {}).get("page") or {}).get("next_cursor") if is_dict(primary.body) else None
    seen = {item.get("mission_id") for item in items if is_dict(item)}
    if next_cursor:
        page2 = client.get("/api/missions?" + urlencode({"limit": 25, "cursor": next_cursor}), "pagination_next")
        items2 = validate_list(report, page2, allow_fixtures)
        report.check(not (seen & {item.get("mission_id") for item in items2 if is_dict(item)}), "live API: cursor page has no duplicate missions")
    else:
        report.skip("cursor continuation", "first page has no next_cursor")
    for item in items[:max_details]:
        href = item.get("detail_href") if is_dict(item) else None
        if isinstance(href, str):
            validate_detail(report, client.get(href, "detail"), allow_fixtures)
    if items and max_details == 0:
        report.skip("Mission detail contracts", "--max-details is zero")
    validate_submission_distinction(report, submission_id, items)


def validate_submission_distinction(report: Report, submission_id: str | None, items: list[dict]) -> None:
    if submission_id is None:
        report.skip("submission_id distinct from mission_id", "provide --submission-id or capture manifest submission_id")
        return
    report.coverage.add("submission_distinct")
    mids = {item.get("mission_id") for item in items if is_dict(item)}
    report.check(submission_id not in mids, "submission_id is distinct from every persistent mission_id")
    report.check(not MISSION_ID.fullmatch(submission_id), "submission_id does not masquerade as m-* persistent ID")


FULL_COVERAGE = {"list", "detail", "empty_list", "timeline", "zero", "findings", "unavailable", "non_applicable", "refused", "timeout", "cancelled", "failed", "incomplete", "unknown", "mcp", "submission_distinct"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AGNT black-box product/API conformance gate")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--base-url", help="live API base URL (or AGNT_API_BASE_URL), e.g. http://127.0.0.1:8141")
    source.add_argument("--capture", type=Path, help="capture manifest JSON")
    parser.add_argument("--submission-id", help="known transient POST /api/runs ID to compare")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds (default: 8)")
    parser.add_argument("--max-details", type=int, default=25, help="maximum live Mission details to validate")
    parser.add_argument("--fixture-mode", action="store_true", help="allow explicit $fixture markers; NEVER use for real API validation")
    parser.add_argument("--require-full-coverage", action="store_true", help="exit 2 when the supplied dataset does not exercise every semantic scenario")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    base_url = args.base_url or (None if args.capture else os.environ.get("AGNT_API_BASE_URL"))
    if not base_url and not args.capture:
        parser.error("provide --base-url, AGNT_API_BASE_URL, or --capture")
    report = Report(verbose=args.verbose)
    check_contract_files(report)
    try:
        if base_url:
            run_live(report, base_url, args.timeout, max(0, args.max_details), args.submission_id, args.fixture_mode)
        else:
            run_capture(report, args.capture.resolve(), args.fixture_mode)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError, AttributeError, TypeError, KeyError) as error:
        report.fail("gate input/transport", str(error))
    missing_coverage = sorted(FULL_COVERAGE - report.coverage)
    if missing_coverage:
        report.skip("full semantic case coverage", ", ".join(missing_coverage))
    report.summary()
    if report.failures:
        return 1
    if args.require_full_coverage and missing_coverage:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
