#!/usr/bin/env python3
"""Dependency-free semantic tests for agnt.execution-status.v1.

The tests prove the dangerous mappings are impossible in the contract fixtures: unavailable,
failed, timed out, cancelled, denied, non-applicable, or incomplete executions cannot become a
proved zero-result state.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
DATA = json.loads((HERE / "fixtures/execution-status-cases.fixture.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((HERE / "execution-status-v1.schema.json").read_text(encoding="utf-8"))
HISTORY = json.loads((HERE / "mission-history-v1.schema.json").read_text(encoding="utf-8"))
TIMELINE = json.loads((HERE / "mission-timeline-v1.schema.json").read_text(encoding="utf-8"))
CASES = {case["case_id"]: case for case in DATA["cases"]}

MISSION = {"en_file", "en_cours", "termine", "refuse", "erreur", "inconnu"}
APPLICABILITY = {"applicable", "non_applicable", "inconnu"}
SELECTION = {"selectionne", "non_selectionne", "inconnu"}
CONDITION = {"remplie", "bloquee", "inconnu"}
AUTHORIZATION = {"autorise", "non_autorise", "non_evalue", "inconnu"}
AVAILABILITY = {"disponible", "indisponible", "inconnu"}
EXECUTION = {"non_lance", "en_cours", "termine", "echoue", "timed_out", "cancelled", "unavailable", "inconnu"}
DETECTION = {"findings_presents", "rien_trouve", "non_evalue", "inconnu"}
PROOFS = {"recorded", "derived", "provider_reported", "unknown"}
FORBIDDEN_KEYS = {
    "endpoint", "url", "uri", "headers", "authorization_header", "cookie", "token",
    "credential", "password", "argv", "command", "environment", "env", "stack",
    "stack_trace", "traceback", "raw_request", "raw_response", "raw_payload", "stderr",
    "absolute_path", "storage_path", "socket",
}
REQUIRED_CASES = {
    "completed_zero_proven", "completed_with_findings", "local_provider_absent",
    "provider_not_applicable", "explicit_policy_refusal", "policy_unavailable_fail_closed",
    "target_not_authorized", "egress_blocked_before_mcp", "rule_pack_invalid",
    "mcp_provider_unavailable", "mcp_timeout", "mcp_cancelled", "remote_provider_error",
    "invalid_provider_output", "findings_artifact_missing",
    "incomplete_journal_and_artifacts", "partial_mcp_provenance_with_valid_findings",
    "unknown_source_status",
}


def records():
    for case in DATA["cases"]:
        for record in case["records"]:
            yield case, record


def walk(value, path="$"):
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{path}[{index}]")


class ExecutionStatusContract(unittest.TestCase):
    def test_fixture_is_explicit_and_all_required_scenarios_exist(self):
        self.assertIn("ANONYMIZED CONTRACT FIXTURE", DATA["$fixture"])
        self.assertEqual(DATA["schema_version"], "agnt.execution-status.v1")
        self.assertEqual(set(CASES), REQUIRED_CASES)

    def test_dimensions_are_present_and_non_overlapping(self):
        dimensions = {
            "applicability": APPLICABILITY,
            "selection": SELECTION,
            "condition": CONDITION,
            "authorization": AUTHORIZATION,
            "availability": AVAILABILITY,
            "execution": EXECUTION,
            "detection": DETECTION,
        }
        vocabularies = list(dimensions.values())
        # `inconnu` and `non_evalue` are intentionally scoped by their dimension; every other
        # term has exactly one semantic dimension and therefore cannot be read ambiguously.
        shared_scoped = {"inconnu", "non_evalue"}
        terms = [term for vocabulary in vocabularies for term in vocabulary if term not in shared_scoped]
        self.assertEqual(len(terms), len(set(terms)))
        overlaps = {term for term in set().union(*vocabularies)
                    if sum(term in vocabulary for vocabulary in vocabularies) > 1}
        self.assertEqual(overlaps, shared_scoped)
        for _, record in records():
            for name, vocabulary in dimensions.items():
                self.assertIn(name, record)
                self.assertIn(record[name]["value"], vocabulary)
                self.assertIn(record[name]["proof"], PROOFS)

    def test_mission_status_vocabulary_is_exactly_history_v1(self):
        history_statuses = set(HISTORY["$defs"]["status"]["enum"])
        self.assertEqual(history_statuses, MISSION)
        self.assertTrue(all(case["mission_status"] in MISSION for case in DATA["cases"]))
        self.assertFalse({"annule", "timeout", "indisponible", "sans_resultat"} & MISSION)

    def test_only_completed_proved_detection_can_have_zero(self):
        zero_records = []
        for _, record in records():
            detection = record["detection"]
            if detection.get("findings_count") == 0:
                zero_records.append(record)
                self.assertEqual(detection["value"], "rien_trouve")
                self.assertGreater(detection["analyzed_targets"], 0)
                self.assertEqual(record["execution"]["value"], "termine")
                self.assertEqual(record["execution"]["invocation"], "oui")
                self.assertEqual(record["execution"]["output"], "exploitable")
                self.assertEqual(record["completeness"]["state"], "complete")
        self.assertEqual(len(zero_records), 1, "fixture must include exactly one proved-zero case")

    def test_absent_failed_denied_timed_out_cancelled_never_map_to_zero(self):
        forbidden_execution = {"non_lance", "echoue", "timed_out", "cancelled", "unavailable", "inconnu"}
        for case, record in records():
            execution = record["execution"]["value"]
            denied = record["authorization"]["value"] in {"non_autorise", "non_evalue"}
            absent = record["availability"]["value"] == "indisponible"
            if execution in forbidden_execution or denied or absent:
                self.assertNotEqual(record["detection"]["value"], "rien_trouve", case["case_id"])
                self.assertNotIn("findings_count", record["detection"], case["case_id"])

    def test_findings_require_positive_normalized_count(self):
        for case, record in records():
            detection = record["detection"]
            if detection["value"] == "findings_presents":
                self.assertGreater(detection["findings_count"], 0, case["case_id"])
                self.assertEqual(record["execution"]["value"], "termine")
                self.assertIn(record["execution"]["output"], {"exploitable", "partiel"})

    def test_policy_unavailable_is_not_explicit_policy_denial(self):
        unavailable = CASES["policy_unavailable_fail_closed"]["records"][0]
        denied = CASES["explicit_policy_refusal"]["records"][0]
        self.assertEqual(unavailable["authorization"]["value"], "non_evalue")
        self.assertEqual(unavailable["authorization"]["reason_code"], "policy_unavailable")
        self.assertEqual(denied["authorization"]["value"], "non_autorise")
        self.assertEqual(denied["authorization"]["reason_code"], "policy_denied")

    def test_timeout_cancellation_unavailability_and_failure_stay_distinct(self):
        values = {
            CASES["mcp_timeout"]["records"][0]["execution"]["value"],
            CASES["mcp_cancelled"]["records"][0]["execution"]["value"],
            CASES["mcp_provider_unavailable"]["records"][0]["execution"]["value"],
            CASES["remote_provider_error"]["records"][0]["execution"]["value"],
        }
        self.assertEqual(values, {"timed_out", "cancelled", "unavailable", "echoue"})

    def test_egress_block_does_not_claim_remote_unavailability(self):
        record = CASES["egress_blocked_before_mcp"]["records"][0]
        self.assertEqual(record["condition"]["value"], "bloquee")
        self.assertEqual(record["availability"]["value"], "inconnu")
        self.assertEqual(record["execution"]["value"], "non_lance")

    def test_missing_findings_and_unknown_status_are_not_non_evidence_zeros(self):
        missing = CASES["findings_artifact_missing"]["records"][0]
        unknown = CASES["unknown_source_status"]["records"][0]
        self.assertEqual(missing["execution"]["value"], "termine")
        self.assertEqual(missing["detection"]["value"], "inconnu")
        self.assertNotIn("findings_count", missing["detection"])
        for name in ("availability", "execution", "detection"):
            self.assertEqual(unknown[name]["value"], "inconnu")
        self.assertIn("unknown_source_status", unknown["completeness"]["limitations"])

    def test_partial_provenance_does_not_invalidate_normalized_findings(self):
        record = CASES["partial_mcp_provenance_with_valid_findings"]["records"][0]
        self.assertEqual(record["detection"]["value"], "findings_presents")
        self.assertEqual(record["detection"]["findings_count"], 1)
        self.assertEqual(record["completeness"]["state"], "partial")
        self.assertIn("provenance_partial", record["completeness"]["limitations"])
        self.assertNotIn("transport", record["provenance"])

    def test_compatibility_with_history_and_timeline_contracts(self):
        self.assertEqual(DATA["schema_version"], "agnt.execution-status.v1")
        self.assertIn("executions", HISTORY["$defs"]["detailResponse"]["properties"]["data"]["properties"])
        self.assertTrue(HISTORY["$defs"]["detailResponse"]["properties"]["data"]["additionalProperties"])
        timeline_consequences = set(TIMELINE["$defs"]["event"]["properties"]["consequence"]["enum"])
        self.assertTrue({"completed", "failed", "unavailable", "unknown"}.issubset(timeline_consequences))
        self.assertNotIn("rien_trouve", timeline_consequences,
                         "detection result must not leak into event consequence")

    def test_no_sensitive_fields_paths_payloads_credentials_or_markup(self):
        for path, value in walk(DATA):
            key = path.rsplit(".", 1)[-1].lower()
            self.assertNotIn(key, FORBIDDEN_KEYS, f"forbidden key at {path}")
            if not isinstance(value, str):
                continue
            self.assertNotIn("/home/", value)
            self.assertNotRegex(value, r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+")
            self.assertNotRegex(value, r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
            self.assertNotRegex(value, r"<\s*(?:script|img|a)\b", f"markup at {path}")
            if re.match(r"^https?://", value):
                parsed = urlsplit(value)
                self.assertIsNone(parsed.username)
                self.assertIsNone(parsed.password)

    def test_schema_enums_match_the_contract_test_vocabularies(self):
        defs = SCHEMA["$defs"]
        def enum_for(name):
            if name in {"applicability", "selection", "condition", "authorization"}:
                return set(defs[name]["allOf"][1]["properties"]["value"]["enum"])
            return set(defs[name]["properties"]["value"]["enum"])
        self.assertEqual(enum_for("applicability"), APPLICABILITY)
        self.assertEqual(enum_for("selection"), SELECTION)
        self.assertEqual(enum_for("condition"), CONDITION)
        self.assertEqual(enum_for("authorization"), AUTHORIZATION)
        self.assertEqual(enum_for("availability"), AVAILABILITY)
        self.assertEqual(enum_for("execution"), EXECUTION)
        self.assertEqual(enum_for("detection"), DETECTION)


if __name__ == "__main__":
    unittest.main(verbosity=2)
