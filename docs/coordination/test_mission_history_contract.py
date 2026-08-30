#!/usr/bin/env python3
"""Dependency-free invariants for the Mission History v1 contract fixtures.

This does more than parse JSON: it checks cross-response identity, lifecycle vocabulary,
truthful optional counts, stable ordering, event ordering, relative locations, provenance
shape, and a conservative forbidden-data boundary.
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
LIST = json.loads((FIXTURES / "mission-history-list.fixture.json").read_text(encoding="utf-8"))
DETAIL = json.loads((FIXTURES / "mission-history-detail.fixture.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((HERE / "mission-history-v1.schema.json").read_text(encoding="utf-8"))
STATUSES = {"en_file", "en_cours", "termine", "refuse", "erreur", "inconnu"}
FORBIDDEN_KEYS = {
    "authorization", "cookie", "set-cookie", "token", "access_token", "refresh_token",
    "password", "passwd", "private_key", "headers", "environment", "env", "argv",
    "stack_trace", "traceback", "absolute_path", "storage_path", "server_url",
}
PROVENANCE_KEYS = {
    "provider_id", "provider_kind", "transport", "server_id", "tool_id", "confidence",
    "availability",
}


def walk(value, path="$"):
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{path}[{index}]")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class MissionHistoryContract(unittest.TestCase):
    def test_fixture_marker_and_version_are_explicit(self):
        for payload in (LIST, DETAIL):
            self.assertIn("ANONYMIZED CONTRACT FIXTURE", payload["$fixture"])
            self.assertEqual(payload["schema_version"], "agnt.history.v1")

    def test_schema_and_contract_use_the_same_lifecycle_vocabulary(self):
        schema_statuses = set(SCHEMA["$defs"]["status"]["enum"])
        self.assertEqual(schema_statuses, STATUSES)
        for item in LIST["items"]:
            self.assertIn(item["status"], STATUSES)

    def test_list_identity_links_and_stable_sort(self):
        items = LIST["items"]
        self.assertTrue(items)
        self.assertEqual(len({item["mission_id"] for item in items}), len(items))
        for item in items:
            self.assertRegex(item["mission_id"], r"^m-[A-Za-z0-9-]+$")
            self.assertEqual(item["detail_href"], f"/api/missions/{item['mission_id']}")
            self.assertNotIn("/home/", json.dumps(item))
        ordering = [(parse_time(x["created_at"]), x["mission_id"]) for x in items]
        self.assertEqual(ordering, sorted(ordering, reverse=True))

    def test_missing_results_are_not_fabricated_as_zero(self):
        refused = next(x for x in LIST["items"] if x["status"] == "refuse")
        unknown = next(x for x in LIST["items"] if x["status"] == "inconnu")
        for item in (refused, unknown):
            self.assertNotIn("findings_summary", item)
            self.assertFalse(item["artifacts"]["findings"])
        self.assertTrue(unknown["incomplete"])

    def test_counts_are_consistent_with_detail(self):
        summary = DETAIL["mission"]
        findings = DETAIL["data"]["findings"]
        counts = summary["findings_summary"]
        self.assertEqual(counts["total"], len(findings))
        self.assertEqual(counts["total"], sum(counts["by_severity"].values()))
        severities = {}
        for finding in findings:
            value = finding["severity"]["value"]
            severities[value] = severities.get(value, 0) + 1
        self.assertEqual(counts["by_severity"], severities)
        list_summary = next(x for x in LIST["items"] if x["mission_id"] == summary["mission_id"])
        self.assertEqual(list_summary, summary)

    def test_detail_references_and_events_are_consistent(self):
        findings = DETAIL["data"]["findings"]
        finding_ids = {finding["id"] for finding in findings}
        for cluster in DETAIL["data"]["clusters"]["clusters"]:
            self.assertTrue(set(cluster["members"]).issubset(finding_ids))
        events = DETAIL["data"]["events"]
        self.assertEqual([e["sequence"] for e in events], sorted(e["sequence"] for e in events))
        self.assertEqual(len({e["sequence"] for e in events}), len(events))
        self.assertTrue(all(parse_time(a["timestamp"]) <= parse_time(b["timestamp"])
                            for a, b in zip(events, events[1:])))

    def test_finding_locations_are_relative_and_provenance_is_additive(self):
        saw_mcp = False
        for finding in DETAIL["data"]["findings"]:
            location = finding.get("location", {})
            if "file" in location:
                self.assertFalse(Path(location["file"]).is_absolute())
                self.assertNotIn("..", Path(location["file"]).parts)
            provenance = finding.get("source", {}).get("provenance")
            if provenance:
                self.assertTrue(set(provenance).issubset(PROVENANCE_KEYS))
                self.assertIn(provenance["provider_kind"], {"local", "mcp", "external"})
                saw_mcp |= provenance["provider_kind"] == "mcp"
        self.assertTrue(saw_mcp)

    def test_no_forbidden_keys_credentials_or_credential_urls(self):
        for payload in (LIST, DETAIL):
            for path, value in walk(payload):
                key = path.rsplit(".", 1)[-1].lower()
                self.assertNotIn(key, FORBIDDEN_KEYS, f"forbidden key at {path}")
                if not isinstance(value, str):
                    continue
                self.assertNotRegex(value, r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+")
                self.assertNotRegex(value, r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
                if re.match(r"^https?://", value):
                    parsed = urlsplit(value)
                    self.assertIsNone(parsed.username, f"URL userinfo at {path}")
                    self.assertIsNone(parsed.password, f"URL password at {path}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
