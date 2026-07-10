import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from crawldex_report import CrawlDexReporter, build_echo_payload, echo
import crawldex_report.core as crawldex_core


class EchoTests(unittest.TestCase):
    def setUp(self):
        self.temp_home = tempfile.TemporaryDirectory()
        self.env_patch = patch.dict(os.environ, {
            "HOME": self.temp_home.name,
            "XDG_CONFIG_HOME": str(Path(self.temp_home.name) / ".config"),
            "APPDATA": str(Path(self.temp_home.name) / "AppData" / "Roaming"),
        })
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()
        self.temp_home.cleanup()

    def test_build_echo_payload_contract(self):
        self.assertEqual(
            build_echo_payload("atr_0123456789abcdef", "overrode", False),
            {
                "record_id": "atr_0123456789abcdef",
                "action_taken": "overrode",
                "task_attempted": False,
            },
        )

    def test_direct_echo_posts_payload(self):
        RecordingHandler.calls = []
        server, thread = start_test_server(RecordingHandler)
        try:
            with patch.dict(os.environ, {"CRAWLDEX_CHANNEL": "Adapter-Playwright"}):
                receipt = echo(
                    "atr_0123456789abcdef",
                    "partial",
                    task_attempted=True,
                    api_origin=f"http://127.0.0.1:{server.server_port}",
                    timeout=1.0,
                )

            self.assertTrue(receipt.accepted)
            self.assertEqual(receipt.endpoint, f"http://127.0.0.1:{server.server_port}/api/v1/echo")
            self.assertEqual(len(RecordingHandler.calls), 1)
            self.assertEqual(RecordingHandler.calls[0]["path"], "/api/v1/echo")
            self.assertRegex(RecordingHandler.calls[0]["headers"].get("x-crawldex-instance", ""), r"^[0-9a-f-]{36}$")
            self.assertEqual(RecordingHandler.calls[0]["headers"].get("x-crawldex-channel"), "adapter-playwright")
            self.assertEqual(
                RecordingHandler.calls[0]["body"],
                {
                    "record_id": "atr_0123456789abcdef",
                    "action_taken": "partial",
                    "task_attempted": True,
                },
            )
        finally:
            stop_test_server(server, thread)

    def test_instance_id_persists_across_calls(self):
        RecordingHandler.calls = []
        server, thread = start_test_server(RecordingHandler)
        try:
            reporter = CrawlDexReporter(
                api_origin=f"http://127.0.0.1:{server.server_port}",
                timeout=1.0,
            )

            first = reporter.echo("atr_0123456789abcdef", "followed")
            second = reporter.echo("atr_0123456789abcdef", "partial")

            self.assertTrue(first.accepted)
            self.assertTrue(second.accepted)
            first_id = RecordingHandler.calls[0]["headers"].get("x-crawldex-instance")
            second_id = RecordingHandler.calls[1]["headers"].get("x-crawldex-instance")
            self.assertRegex(first_id or "", r"^[0-9a-f-]{36}$")
            self.assertEqual(second_id, first_id)
            self.assertTrue((Path(self.temp_home.name) / ".config" / "crawldex" / "instance-id").exists())
        finally:
            stop_test_server(server, thread)

    def test_direct_echo_falls_back_after_vercel_challenge(self):
        ChallengeHandler.calls = []
        RecordingHandler.calls = []
        challenge_server, challenge_thread = start_test_server(ChallengeHandler)
        fallback_server, fallback_thread = start_test_server(RecordingHandler)
        try:
            with patch.object(crawldex_core, "DEFAULT_API_ORIGINS", (f"http://127.0.0.1:{fallback_server.server_port}",)):
                receipt = echo(
                    "atr_0123456789abcdef",
                    "partial",
                    task_attempted=True,
                    api_origin=f"http://127.0.0.1:{challenge_server.server_port}",
                    timeout=1.0,
                )

            self.assertTrue(receipt.accepted)
            self.assertEqual(receipt.endpoint, f"http://127.0.0.1:{fallback_server.server_port}/api/v1/echo")
            self.assertEqual(len(ChallengeHandler.calls), 1)
            self.assertEqual(len(RecordingHandler.calls), 1)
        finally:
            stop_test_server(challenge_server, challenge_thread)
            stop_test_server(fallback_server, fallback_thread)

    def test_direct_echo_does_not_fall_back_after_plain_500(self):
        ServerErrorHandler.calls = []
        RecordingHandler.calls = []
        first_server, first_thread = start_test_server(ServerErrorHandler)
        fallback_server, fallback_thread = start_test_server(RecordingHandler)
        try:
            with patch.object(crawldex_core, "DEFAULT_API_ORIGINS", (f"http://127.0.0.1:{fallback_server.server_port}",)):
                receipt = echo(
                    "atr_0123456789abcdef",
                    "partial",
                    task_attempted=True,
                    api_origin=f"http://127.0.0.1:{first_server.server_port}",
                    timeout=1.0,
                )

            self.assertFalse(receipt.accepted)
            self.assertTrue(receipt.fail_open)
            self.assertEqual(receipt.endpoint, f"http://127.0.0.1:{first_server.server_port}/api/v1/echo")
            self.assertIn("HTTP 500", receipt.warning)
            self.assertEqual(len(ServerErrorHandler.calls), 1)
            self.assertEqual(RecordingHandler.calls, [])
        finally:
            stop_test_server(first_server, first_thread)
            stop_test_server(fallback_server, fallback_thread)

    def test_auto_report_off_by_default_makes_no_extra_echo_request(self):
        RecordingHandler.calls = []
        server, thread = start_test_server(RecordingHandler)
        try:
            reporter = CrawlDexReporter(
                report_url=f"http://127.0.0.1:{server.server_port}/api/v1/runs",
                timeout=1.0,
            )

            receipt = reporter.report(
                {
                    "site": "example.com",
                    "task": "subscriptions.cancel",
                    "outcome": "blocked",
                    "record_id": "atr_0123456789abcdef",
                }
            )

            self.assertTrue(receipt.accepted)
            self.assertEqual([call["path"] for call in RecordingHandler.calls], ["/api/v1/runs"])
        finally:
            stop_test_server(server, thread)

    def test_auto_report_emits_echo_after_redacted_outcome_report(self):
        RecordingHandler.calls = []
        server, thread = start_test_server(RecordingHandler)
        try:
            reporter = CrawlDexReporter(
                report_url=f"http://127.0.0.1:{server.server_port}/api/v1/runs",
                auto_report=True,
                timeout=1.0,
            )

            receipt = reporter.report(
                {
                    "site": "example.com",
                    "task": "subscriptions.cancel",
                    "outcome": "success_with_handoff",
                    "record_id": "atr_0123456789abcdef",
                    "evidence": {
                        "artifact": {
                            "url": "https://example.com/account?token=secret",
                            "email": "jane@example.com",
                            "authorization": "Bearer secret-token",
                        },
                        "redaction_status": "redacted",
                    },
                }
            )

            self.assertTrue(receipt.accepted)
            self.assertEqual([call["path"] for call in RecordingHandler.calls], ["/api/v1/runs", "/api/v1/echo"])
            report_json = json.dumps(RecordingHandler.calls[0]["body"], sort_keys=True)
            self.assertIn("sha256:", report_json)
            self.assertNotIn("jane@example.com", report_json)
            self.assertNotIn("secret-token", report_json)
            self.assertNotIn("token=secret", report_json)
            self.assertEqual(
                RecordingHandler.calls[1]["body"],
                {
                    "record_id": "atr_0123456789abcdef",
                    "action_taken": "followed",
                    "task_attempted": True,
                },
            )
        finally:
            stop_test_server(server, thread)

    def test_opt_out_omits_instance_without_suppressing_auto_report_echo(self):
        RecordingHandler.calls = []
        server, thread = start_test_server(RecordingHandler)
        try:
            reporter = CrawlDexReporter(
                report_url=f"http://127.0.0.1:{server.server_port}/api/v1/runs",
                auto_report=True,
                timeout=1.0,
            )

            with patch.dict(os.environ, {"CRAWLDEX_NO_INSTANCE_ID": "1"}):
                receipt = reporter.report(
                    {
                        "site": "example.com",
                        "task": "subscriptions.cancel",
                        "outcome": "blocked",
                        "record_id": "atr_0123456789abcdef",
                    }
                )

            self.assertTrue(receipt.accepted)
            self.assertEqual([call["path"] for call in RecordingHandler.calls], ["/api/v1/runs", "/api/v1/echo"])
            self.assertNotIn("x-crawldex-instance", RecordingHandler.calls[0]["headers"])
            self.assertNotIn("x-crawldex-instance", RecordingHandler.calls[1]["headers"])
            self.assertFalse((Path(self.temp_home.name) / ".config" / "crawldex" / "instance-id").exists())
        finally:
            stop_test_server(server, thread)

    def test_opt_out_omits_instance_without_suppressing_direct_echo(self):
        RecordingHandler.calls = []
        server, thread = start_test_server(RecordingHandler)
        try:
            reporter = CrawlDexReporter(
                api_origin=f"http://127.0.0.1:{server.server_port}",
                timeout=1.0,
            )

            with patch.dict(os.environ, {"CRAWLDEX_NO_INSTANCE_ID": "1"}):
                receipt = reporter.echo("atr_0123456789abcdef", "followed")

            self.assertTrue(receipt.accepted)
            self.assertEqual([call["path"] for call in RecordingHandler.calls], ["/api/v1/echo"])
            self.assertNotIn("x-crawldex-instance", RecordingHandler.calls[0]["headers"])
        finally:
            stop_test_server(server, thread)

    def test_unavailable_config_path_degrades_without_instance_header(self):
        blocked_config_path = Path(self.temp_home.name) / "not-a-directory"
        blocked_config_path.write_text("", encoding="utf-8")
        RecordingHandler.calls = []
        server, thread = start_test_server(RecordingHandler)
        try:
            reporter = CrawlDexReporter(
                api_origin=f"http://127.0.0.1:{server.server_port}",
                timeout=1.0,
            )

            with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(blocked_config_path)}):
                receipt = reporter.echo("atr_0123456789abcdef", "followed")

            self.assertTrue(receipt.accepted)
            self.assertEqual([call["path"] for call in RecordingHandler.calls], ["/api/v1/echo"])
            self.assertNotIn("x-crawldex-instance", RecordingHandler.calls[0]["headers"])
        finally:
            stop_test_server(server, thread)


class RecordingHandler(BaseHTTPRequestHandler):
    calls = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        headers = {key.lower(): value for key, value in self.headers.items()}
        type(self).calls.append({"path": self.path, "body": body, "headers": headers})
        if self.path == "/api/v1/echo":
            self._send_json({"status": "accepted"}, status=202)
        else:
            self._send_json({"run": {"id": "run_test", "source_tier": "anonymous_report"}})

    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class ChallengeHandler(BaseHTTPRequestHandler):
    calls = []

    def do_POST(self):
        type(self).calls.append({"path": self.path})
        body = b"<html>Vercel Security Checkpoint challenge</html>"
        self.send_response(403)
        self.send_header("Content-Type", "text/html")
        self.send_header("x-vercel-mitigated", "challenge")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class ServerErrorHandler(BaseHTTPRequestHandler):
    calls = []

    def do_POST(self):
        type(self).calls.append({"path": self.path})
        body = b'{"error":"server_error"}'
        self.send_response(500)
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


if __name__ == "__main__":
    unittest.main()
