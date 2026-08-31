#!/usr/bin/env python3
"""Self-tests for the black-box gate, including a real ephemeral HTTP server."""
from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
COORD = HERE.parent
EXAMPLE = HERE / "examples/anonymized-capture"
spec = importlib.util.spec_from_file_location("product_api_gate", HERE / "product_api_gate.py")
gate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gate
spec.loader.exec_module(gate)


def load(name):
    return json.loads((EXAMPLE / name).read_text(encoding="utf-8"))


def strip_fixture(value):
    if isinstance(value, dict):
        return {key: strip_fixture(child) for key, child in value.items() if key != "$fixture"}
    if isinstance(value, list):
        return [strip_fixture(child) for child in value]
    return value


class Handler(BaseHTTPRequestHandler):
    listing = strip_fixture(load("list.json"))
    detail = strip_fixture(load("detail.json"))

    def do_GET(self):  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/api/missions":
            query = parse_qs(parsed.query)
            status = query.get("status", [None])[-1]
            if status == "__agnt_invalid_status__":
                return self.send_json(400, {"error": {"code": "INVALID_STATUS_FILTER", "message": "Statut invalide"}})
            items = copy.deepcopy(self.listing["items"])
            if status:
                items = [item for item in items if item["status"] == status]
            target_type = query.get("target_type", [None])[-1]
            if target_type:
                items = [item for item in items if item["target"]["type"] == target_type]
            limit = int(query.get("limit", [25])[-1])
            return self.send_json(200, {"schema_version": gate.HISTORY_VERSION,
                                        "items": items[:limit],
                                        "page": {"limit": limit, "next_cursor": None}})
        if parsed.path == "/api/missions/m-20260830T101500Z-a1b2c3d4":
            return self.send_json(200, copy.deepcopy(self.detail))
        self.send_json(404, {"error": {"code": "NOT_FOUND", "message": "Introuvable"}})

    def send_json(self, status, body):
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_args):
        pass


class ProductApiGateTests(unittest.TestCase):
    def test_anonymized_capture_conforms_only_in_fixture_mode(self):
        report = gate.Report()
        gate.run_capture(report, EXAMPLE / "capture-manifest.json", allow_fixtures=True)
        self.assertFalse(report.failures, report.failures[:3])
        self.assertTrue({"list", "detail", "empty_list", "timeline", "findings", "mcp", "submission_distinct"} <= report.coverage)

    def test_real_mode_rejects_fixture_or_demo_markers(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = gate.main(["--capture", str(EXAMPLE / "capture-manifest.json")])
        self.assertEqual(code, 1)

    def test_require_full_coverage_uses_distinct_exit_code(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = gate.main(["--capture", str(EXAMPLE / "capture-manifest.json"),
                              "--fixture-mode", "--require-full-coverage"])
        self.assertEqual(code, 2)

    def test_black_box_live_http_validation(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            report = gate.Report()
            gate.run_live(report, f"http://127.0.0.1:{server.server_port}", timeout=2,
                          max_details=1, submission_id="submission-anonymized-01",
                          allow_fixtures=False)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertFalse(report.failures, report.failures[:5])
        self.assertTrue({"list", "detail", "timeline", "findings", "mcp", "submission_distinct"} <= report.coverage)

    def test_full_execution_semantic_matrix_is_exercisable(self):
        matrix = json.loads((COORD / "fixtures/execution-status-cases.fixture.json").read_text(encoding="utf-8"))
        report = gate.Report()
        for case in matrix["cases"]:
            for index, record in enumerate(case["records"]):
                gate.validate_execution(report, record, f"{case['case_id']}[{index}]")
        self.assertFalse(report.failures, report.failures[:5])
        self.assertTrue({"zero", "findings", "unavailable", "non_applicable", "refused",
                         "timeout", "cancelled", "failed", "incomplete", "unknown", "mcp"}
                        <= report.coverage)

    def test_unavailable_or_failed_execution_cannot_claim_zero(self):
        record = copy.deepcopy(load("detail.json")["data"]["executions"][0])
        record["availability"] = {"value": "indisponible", "proof": "recorded", "reason_code": "binary_missing"}
        record["execution"] = {"value": "unavailable", "invocation": "non", "output": "non_exploitable", "proof": "recorded"}
        record["detection"] = {"value": "rien_trouve", "findings_count": 0, "analyzed_targets": 1, "proof": "recorded"}
        report = gate.Report()
        with contextlib.redirect_stderr(io.StringIO()):
            gate.validate_execution(report, record, "malicious-zero")
        self.assertTrue(any("zero" in failure for failure in report.failures))

    def test_missing_findings_rejects_fabricated_data_and_summary(self):
        detail = copy.deepcopy(strip_fixture(load("detail.json")))
        detail["missing_artifacts"] = ["findings"]
        response = gate.Response("/api/missions/m-20260830T101500Z-a1b2c3d4", 200, detail, "detail")
        report = gate.Report()
        with contextlib.redirect_stderr(io.StringIO()):
            gate.validate_detail(report, response, allow_fixtures=False)
        self.assertTrue(any("missing findings" in failure for failure in report.failures))
        self.assertTrue(any("no zero/count summary" in failure for failure in report.failures))

    def test_sensitive_backend_payload_fails_clearly(self):
        payload = {"schema_version": gate.HISTORY_VERSION, "items": [],
                   "page": {"limit": 25, "next_cursor": None},
                   "raw_payload": "Bearer example-secret-value"}
        report = gate.Report()
        with contextlib.redirect_stderr(io.StringIO()):
            gate.validate_list(report, gate.Response("/api/missions", 200, payload), False)
        self.assertTrue(any("forbidden field" in failure for failure in report.failures))
        self.assertTrue(any("credential-like" in failure for failure in report.failures))

    def test_capture_body_cannot_escape_manifest_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "capture.json"
            manifest.write_text(json.dumps({"responses": [{"path": "/api/missions", "status": 200,
                                                             "body_file": "../outside.json"}]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "escapes"):
                gate.load_capture(manifest)


if __name__ == "__main__":
    unittest.main(verbosity=2)
