import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import threading
import time
import unittest
from unittest.mock import patch

from crawldex_report import CrawlDexReporter, trust_record_from_response
import crawldex_report.core as crawldex_core


class TrustRecordTests(unittest.TestCase):
    def test_trust_record_happy_path(self):
        RecordingTrustRecordHandler.request_path = None
        server, thread = start_test_server(RecordingTrustRecordHandler)
        try:
            reporter = CrawlDexReporter(api_origin=f"http://127.0.0.1:{server.server_port}", timeout=1.0)

            record = reporter.trust_record("netflix.com", "subscriptions.cancel")

            self.assertFalse(record.fail_open)
            self.assertEqual(record.record_id, "atr_fixture_001")
            self.assertEqual(record.verdict, "proceed_with_guardrails")
            self.assertEqual(record.known_blockers[0]["code"], "login_required")
            self.assertEqual(RecordingTrustRecordHandler.request_path, "/api/v1/trust-record/netflix.com/subscriptions.cancel")
        finally:
            stop_test_server(server, thread)

    def test_trust_record_falls_back_after_dead_head_origin(self):
        RecordingTrustRecordHandler.request_path = None
        server, thread = start_test_server(RecordingTrustRecordHandler)
        try:
            fallback_origin = f"http://127.0.0.1:{server.server_port}"
            with patch.object(crawldex_core, "DEFAULT_API_ORIGINS", (fallback_origin,)):
                reporter = CrawlDexReporter(api_origin="http://127.0.0.1:1", timeout=1.0)
                record = reporter.trust_record("netflix.com", "subscriptions.cancel")

            self.assertFalse(record.fail_open)
            self.assertEqual(record.record_id, "atr_fixture_001")
            self.assertEqual(RecordingTrustRecordHandler.request_path, "/api/v1/trust-record/netflix.com/subscriptions.cancel")
        finally:
            stop_test_server(server, thread)

    def test_trust_record_uses_env_origin_as_chain_head(self):
        RecordingTrustRecordHandler.request_path = None
        server, thread = start_test_server(RecordingTrustRecordHandler)
        try:
            env_origin = f"http://127.0.0.1:{server.server_port}"
            with patch.dict("os.environ", {"CRAWLDEX_API_ORIGIN": env_origin}):
                reporter = CrawlDexReporter(timeout=1.0)
                record = reporter.trust_record("netflix.com", "subscriptions.cancel")

            self.assertFalse(record.fail_open)
            self.assertEqual(record.record_id, "atr_fixture_001")
            self.assertEqual(RecordingTrustRecordHandler.request_path, "/api/v1/trust-record/netflix.com/subscriptions.cancel")
        finally:
            stop_test_server(server, thread)

    def test_trust_record_timeout_fails_open_with_five_second_cap(self):
        server, thread = start_test_server(SlowTrustRecordHandler)
        try:
            reporter = CrawlDexReporter(api_origin=f"http://127.0.0.1:{server.server_port}", timeout=0.01)

            record = reporter.trust_record("netflix.com", "subscriptions.cancel")

            self.assertTrue(record.fail_open)
            self.assertIsNone(record.record_id)
            self.assertEqual(record.verdict, "unknown")
            self.assertIn("failed open", record.warning)
        finally:
            stop_test_server(server, thread)

    def test_trust_record_malformed_payload_fails_open(self):
        server, thread = start_test_server(MalformedTrustRecordHandler)
        try:
            reporter = CrawlDexReporter(api_origin=f"http://127.0.0.1:{server.server_port}", timeout=1.0)

            record = reporter.trust_record("netflix.com", "subscriptions.cancel")

            self.assertTrue(record.fail_open)
            self.assertIsNone(record.record_id)
            self.assertIn("invalid response", record.warning)
            self.assertIn("site must be a string", record.warning)
        finally:
            stop_test_server(server, thread)

    def test_trust_record_parser_top_level_fields_match_openapi_schema(self):
        parsed = trust_record_from_response(trust_record_fixture())
        parser_fields = set(parsed.as_dict().keys()) - {"warning", "fail_open", "raw"}
        openapi_fields = trust_record_openapi_required_fields()

        self.assertEqual(parser_fields, openapi_fields)


class RecordingTrustRecordHandler(BaseHTTPRequestHandler):
    request_path = None

    def do_GET(self):
        type(self).request_path = self.path
        body = json.dumps(trust_record_fixture()).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class SlowTrustRecordHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(0.2)
        body = json.dumps(trust_record_fixture()).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def log_message(self, format, *args):
        return


class MalformedTrustRecordHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = trust_record_fixture()
        payload["site"] = 123
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def start_test_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def stop_test_server(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(timeout=1)


def trust_record_openapi_required_fields():
    root = Path(__file__).resolve().parents[3]
    source = (root / "src" / "server" / "openapi.ts").read_text(encoding="utf-8")
    start = source.index("TrustRecord: objectSchema")
    end = source.index("TrustRecordBatchRequest:", start)
    segment = source[start:end]
    for required in re.findall(r"\[([^\]]+)\]", segment):
        fields = set(re.findall(r'"([^"]+)"', required))
        if {"atr_version", "record_id", "agent_instruction", "how_to_improve"}.issubset(fields):
            return fields
    raise AssertionError("TrustRecord OpenAPI schema required fields not found")


def trust_record_fixture():
    return {
        "atr_version": "0.1",
        "site": "netflix.com",
        "task": "subscriptions.cancel",
        "issued_at": "2026-07-02T20:00:00.000Z",
        "record_id": "atr_fixture_001",
        "verdict": "proceed_with_guardrails",
        "confidence": 0.72,
        "accessibility": {
            "reachable": True,
            "agent_hostility": "low",
            "success_rate": 0.7,
            "handoff_rate": 0.2,
            "blocked_rate": 0.1,
            "n": 10,
            "last_verified": "2026-07-02T20:00:00.000Z",
        },
        "safety": {
            "canonical": True,
            "canonical_alternative": None,
            "domain_risk": "low",
            "notes": [],
        },
        "freshness": {
            "median_evidence_age_days": 4,
            "surface_last_changed": "2026-07-02T20:00:00.000Z",
            "stale": False,
        },
        "task_compatibility": {
            "supported": True,
            "expected_steps": 5,
            "recipe_available": True,
            "alternatives": [],
        },
        "known_blockers": [
            {
                "code": "login_required",
                "severity": "medium",
                "description": "Login may be required before subscription settings.",
            }
        ],
        "user_present": {
            "required": True,
            "reasons": ["auth"],
            "irreversible_action": "unknown",
        },
        "agent_instruction": "Proceed with guardrails and keep the user available for authentication.",
        "evidence": {
            "sources": {"accepted_public_observation": 2},
            "canonical_url": "https://crawldex.com/sites/netflix.com/subscriptions.cancel",
            "dispute_url": "https://crawldex.com/disputes?site=netflix.com&task=subscriptions.cancel",
        },
        "publisher": {
            "claimed": False,
            "statement": None,
        },
        "how_to_improve": "Submit fresh public evidence.",
    }


if __name__ == "__main__":
    unittest.main()
