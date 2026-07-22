import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
import unittest
from unittest.mock import patch

from crawldex_report import CrawlDexReporter, trust_record_from_response
import crawldex_report.core as crawldex_core


TRUST_RECORD_REQUIRED_FIELDS = {
    "atr_version",
    "site",
    "task",
    "issued_at",
    "record_id",
    "verdict",
    "confidence",
    "accessibility",
    "safety",
    "freshness",
    "task_compatibility",
    "known_blockers",
    "user_present",
    "agent_instruction",
    "evidence",
    "publisher",
    "how_to_improve",
}


class TrustRecordTests(unittest.TestCase):
    def test_trust_record_happy_path(self):
        RecordingTrustRecordHandler.request_path = None
        RecordingTrustRecordHandler.request_headers = {}
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

    def test_trust_record_sends_configured_agent_key(self):
        RecordingTrustRecordHandler.request_path = None
        RecordingTrustRecordHandler.request_headers = {}
        server, thread = start_test_server(RecordingTrustRecordHandler)
        try:
            reporter = CrawlDexReporter(
                api_origin=f"http://127.0.0.1:{server.server_port}",
                agent_key="aa_trust_record_test_key",
                timeout=1.0,
            )
            record = reporter.trust_record("netflix.com", "subscriptions.cancel")

            self.assertFalse(record.fail_open)
            self.assertEqual(
                RecordingTrustRecordHandler.request_headers.get("x-crawldex-agent-key"),
                "aa_trust_record_test_key",
            )
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

    def test_trust_record_parser_top_level_fields_match_published_contract(self):
        parsed = trust_record_from_response(trust_record_fixture())
        parser_fields = set(parsed.as_dict().keys()) - {"warning", "fail_open", "raw"}
        self.assertEqual(parser_fields, TRUST_RECORD_REQUIRED_FIELDS)


class RecordingTrustRecordHandler(BaseHTTPRequestHandler):
    request_path = None
    request_headers = {}

    def do_GET(self):
        type(self).request_path = self.path
        type(self).request_headers = {key.lower(): value for key, value in self.headers.items()}
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
