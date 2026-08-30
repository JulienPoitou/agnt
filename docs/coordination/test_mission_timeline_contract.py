#!/usr/bin/env python3
"""Dependency-free semantic checks for agnt.timeline.v1 fixtures and integration.

Checks contract behavior rather than only JSON syntax: deterministic journal order/identity,
explicit missing time, no Run fabrication on pre-Run refusal, provenance allowlisting,
truncation invariants, and forbidden-data boundaries.
"""
from __future__ import annotations

import json
import re
import unittest
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
COMPLETE = json.loads((FIXTURES / "mission-timeline-complete.fixture.json").read_text(encoding="utf-8"))
PARTIAL = json.loads((FIXTURES / "mission-timeline-refused-partial.fixture.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((HERE / "mission-timeline-v1.schema.json").read_text(encoding="utf-8"))
HISTORY_SCHEMA = json.loads((HERE / "mission-history-v1.schema.json").read_text(encoding="utf-8"))

PROVENANCE_KEYS = {
    "provider_id", "provider_kind", "transport", "server_id", "tool_id", "protocol",
    "confidence", "availability", "request_id", "correlation_id",
}
FORBIDDEN_KEYS = {
    "endpoint", "url", "uri", "headers", "authorization", "cookie", "token", "credential",
    "password", "argv", "command", "environment", "env", "stack", "stack_trace", "traceback",
    "raw_request", "raw_response", "stderr", "absolute_path", "storage_path", "socket",
}


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def walk(value, path="$"):
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{path}[{index}]")


class MissionTimelineContract(unittest.TestCase):
    def test_fixture_markers_and_versions(self):
        for timeline in (COMPLETE, PARTIAL):
            self.assertIn("ANONYMIZED CONTRACT FIXTURE", timeline["$fixture"])
            self.assertEqual(timeline["schema_version"], "agnt.timeline.v1")
            self.assertEqual(timeline["ordering"], "journal_sequence_ascending")

    def test_history_v1_accepts_additive_companion_without_breaking_legacy_events(self):
        data_schema = HISTORY_SCHEMA["$defs"]["detailResponse"]["properties"]["data"]
        self.assertTrue(data_schema["additionalProperties"])
        self.assertIn("events", data_schema["properties"])

    def test_event_order_identity_and_position_are_deterministic(self):
        for timeline in (COMPLETE, PARTIAL):
            events = timeline["events"]
            sequences = [event["source"]["sequence"] for event in events]
            self.assertEqual(sequences, sorted(sequences))
            self.assertEqual(len(sequences), len(set(sequences)))
            self.assertEqual([event["position"] for event in events], list(range(1, len(events) + 1)))
            for event in events:
                mission_id = event["references"]["mission_id"]
                sequence = event["source"]["sequence"]
                self.assertEqual(event["event_id"], f"{mission_id}:{sequence}")

    def test_recorded_timestamps_are_monotonic_but_not_used_as_identity(self):
        times = [parse_time(e["time"]["timestamp"]) for e in COMPLETE["events"]
                 if e["time"]["state"] == "recorded"]
        self.assertEqual(times, sorted(times))
        for event in COMPLETE["events"]:
            self.assertNotIn(event["time"]["timestamp"], event["event_id"])

    def test_missing_timestamp_is_explicit_and_never_filled(self):
        unknown = next(event for event in PARTIAL["events"] if event["category"] == "unknown")
        self.assertEqual(unknown["time"], {"state": "unavailable"})
        self.assertIn("timestamp_missing", unknown["limitations"])
        self.assertIn("timestamp_missing", PARTIAL["limitations"])

    def test_refusal_before_run_does_not_fabricate_run_or_execution(self):
        self.assertEqual(PARTIAL["events"][-1]["consequence"], "refused")
        for event in PARTIAL["events"]:
            self.assertNotIn("run_id", event["references"])
            self.assertNotEqual(event["kind"], "provider_completed")
            self.assertNotEqual(event["kind"], "execution_context_created")

    def test_unknown_event_is_visible_but_payload_is_not_forwarded(self):
        unknown = next(event for event in PARTIAL["events"] if event["category"] == "unknown")
        self.assertEqual(unknown["kind"], "unknown_event_recorded")
        self.assertEqual(unknown["visibility"], "technical")
        self.assertEqual(unknown["data_state"], "unavailable")
        self.assertRegex(unknown["source"]["source_kind"], r"^[a-z0-9_.-]{1,64}$")
        self.assertEqual(set(unknown), {
            "event_id", "position", "source", "time", "category", "kind", "consequence",
            "visibility", "safe_summary", "references", "data_state", "limitations",
        })

    def test_counts_and_truncation_envelope_are_truthful(self):
        for timeline in (COMPLETE, PARTIAL):
            self.assertEqual(timeline["returned_events"], len(timeline["events"]))
            self.assertGreaterEqual(timeline["total_events"], timeline["returned_events"])
            self.assertEqual(timeline["truncated"], timeline["next_cursor"] is not None)
            if timeline["state"] == "complete":
                self.assertFalse(timeline["limitations"])

    def test_mcp_provenance_is_allowlisted_and_confidence_has_basis(self):
        mcp = next(event for event in COMPLETE["events"]
                   if event.get("provenance", {}).get("provider_kind") == "mcp")
        provenance = mcp["provenance"]
        self.assertTrue(set(provenance).issubset(PROVENANCE_KEYS))
        self.assertEqual(provenance["confidence"]["basis"], "provider_declared")
        self.assertIn(provenance["confidence"]["level"], {"low", "medium", "high", "unknown"})
        self.assertNotEqual(provenance["correlation_id"], "cluster-anonymized-01")

    def test_no_forbidden_keys_secrets_paths_markup_or_credential_urls(self):
        for timeline in (COMPLETE, PARTIAL):
            for path, value in walk(timeline):
                key = path.rsplit(".", 1)[-1].lower()
                self.assertNotIn(key, FORBIDDEN_KEYS, f"forbidden key at {path}")
                if not isinstance(value, str):
                    continue
                self.assertNotIn("/home/", value)
                self.assertNotRegex(value, r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+")
                self.assertNotRegex(value, r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
                self.assertNotRegex(value, r"<\s*(?:script|img|a)\b", f"markup at {path}")
                self.assertFalse(any(ord(char) < 32 and char not in "\t\n\r" for char in value))
                if re.match(r"^https?://", value):
                    parsed = urlsplit(value)
                    self.assertIsNone(parsed.username)
                    self.assertIsNone(parsed.password)

    def test_schema_enums_cover_fixture_values(self):
        defs = SCHEMA["$defs"]
        event_props = defs["event"]["properties"]
        states = set(SCHEMA["properties"]["state"]["enum"])
        categories = set(event_props["category"]["enum"])
        consequences = set(event_props["consequence"]["enum"])
        visibilities = set(event_props["visibility"]["enum"])
        data_states = set(event_props["data_state"]["enum"])
        limitations = set(defs["limitation"]["enum"])
        for timeline in (COMPLETE, PARTIAL):
            self.assertIn(timeline["state"], states)
            self.assertTrue(set(timeline["limitations"]).issubset(limitations))
            for event in timeline["events"]:
                self.assertIn(event["category"], categories)
                self.assertIn(event["consequence"], consequences)
                self.assertIn(event["visibility"], visibilities)
                self.assertIn(event["data_state"], data_states)
                self.assertTrue(set(event["limitations"]).issubset(limitations))


if __name__ == "__main__":
    unittest.main(verbosity=2)
