import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
import unittest

from crawldex_report import CrawlDexReporter


class FailOpenTests(unittest.TestCase):
    def test_report_network_error_returns_warning_receipt(self):
        reporter = CrawlDexReporter(report_url="http://127.0.0.1:1/api/v1/runs", timeout=0.1)

        with self.assertLogs("crawldex_report", level=logging.WARNING) as logs:
            receipt = reporter.report(
                {
                    "site": "example.com",
                    "task": "subscriptions.cancel",
                    "outcome": "blocked",
                }
            )

        self.assertFalse(receipt.accepted)
        self.assertTrue(receipt.fail_open)
        self.assertEqual(receipt.acceptance, "fail_open")
        self.assertIn("failed open", receipt.warning)
        self.assertTrue(any("failed open" in entry for entry in logs.output))

    def test_preflight_network_error_returns_typed_fail_open_verdict(self):
        reporter = CrawlDexReporter(report_url="http://127.0.0.1:1/api/v1/runs", timeout=0.1)

        with self.assertLogs("crawldex_report", level=logging.WARNING):
            verdict = reporter.preflight("example.com", "subscriptions.cancel")

        self.assertTrue(verdict.fail_open)
        self.assertEqual(verdict.verdict, "unavailable")
        self.assertIsNone(verdict.outcome_rate)
        self.assertEqual(verdict.blockers, ())
        self.assertEqual(verdict.handoff_likelihood, "unknown")
        self.assertEqual(verdict.freshness["status"], "unknown")

    def test_preflight_malformed_success_response_fails_open(self):
        server, thread = start_test_server(MalformedPreflightHandler)
        try:
            reporter = CrawlDexReporter(report_url=f"http://127.0.0.1:{server.server_port}/api/v1/runs", timeout=1.0)

            with self.assertLogs("crawldex_report", level=logging.WARNING):
                verdict = reporter.preflight("example.com", "subscriptions.cancel")

            self.assertTrue(verdict.fail_open)
            self.assertEqual(verdict.verdict, "unavailable")
            self.assertIn("invalid response", verdict.warning)
        finally:
            stop_test_server(server, thread)

    def test_report_non_json_200_response_fails_open_with_body_preview(self):
        server, thread = start_test_server(NonJsonHandler)
        try:
            reporter = CrawlDexReporter(report_url=f"http://127.0.0.1:{server.server_port}/api/v1/runs", timeout=1.0)

            with self.assertLogs("crawldex_report", level=logging.WARNING):
                receipt = reporter.report(
                    {
                        "site": "example.com",
                        "task": "subscriptions.cancel",
                        "outcome": "blocked",
                    }
                )

            self.assertFalse(receipt.accepted)
            self.assertTrue(receipt.fail_open)
            self.assertIn("non-JSON response", receipt.warning)
            self.assertIn("<html>not json</html>", receipt.warning)
        finally:
            stop_test_server(server, thread)

    def test_report_timeout_fails_open(self):
        server, thread = start_test_server(SlowJsonHandler)
        try:
            reporter = CrawlDexReporter(report_url=f"http://127.0.0.1:{server.server_port}/api/v1/runs", timeout=0.01)

            with self.assertLogs("crawldex_report", level=logging.WARNING):
                receipt = reporter.report(
                    {
                        "site": "example.com",
                        "task": "subscriptions.cancel",
                        "outcome": "blocked",
                    }
                )

            self.assertFalse(receipt.accepted)
            self.assertTrue(receipt.fail_open)
            self.assertIn("timed out", receipt.warning)
        finally:
            stop_test_server(server, thread)


class NonJsonHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = b"<html>not json</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class SlowJsonHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        time.sleep(0.2)
        body = b"{}"
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


class MalformedPreflightHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = b'{"decision":{"recommendation":"proceed_with_guardrails"},"score":{"outcome_rate":2}}'
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


if __name__ == "__main__":
    unittest.main()
