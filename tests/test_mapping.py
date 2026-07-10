import re
import unittest

from crawldex_report import CrawlDexReporter, map_to_run_report


class MappingTests(unittest.TestCase):
    def test_maps_snake_case_input_to_exact_run_payload(self):
        payload = map_to_run_report(
            {
                "site": "demo-shop.crawldex.com",
                "task": "commerce.checkout",
                "agent_profile": {
                    "stack": "browser-use",
                    "model": "gpt-5.5",
                    "browser_runtime": "chromium",
                    "capabilities": {"evidence_redaction": "redacted"},
                },
                "outcome": "success_with_handoff",
                "friction": ["login_required", "2fa_user_present"],
                "steps": 41,
                "duration_sec": 312,
                "token_cost_usd": 0.02,
                "access_fee_usd": 0,
                "source_tier": "anonymous_report",
                "evidence": {
                    "id": "ev-demo-checkout-2026-06-08",
                    "artifact": {
                        "signals": ["confirmation_visible"],
                        "url": "https://example.com/checkout?token=secret",
                    },
                    "artifact_types": ["redacted_trace"],
                    "redaction_status": "redacted",
                },
                "reporter": {"id": "local-agent", "attestation_type": "api_key"},
                "occurred_at": "2026-06-08T16:05:12Z",
                "unknown_field": "ignored",
            }
        )

        self.assertEqual(
            set(payload),
            {
                "site",
                "task",
                "agent_profile",
                "outcome",
                "friction",
                "steps",
                "duration_sec",
                "token_cost_usd",
                "access_fee_usd",
                "source_tier",
                "evidence",
                "reporter",
                "occurred_at",
            },
        )
        self.assertEqual(payload["duration_sec"], 312)
        self.assertEqual(payload["evidence"]["artifact_types"], ["redacted_trace"])
        self.assertNotIn("artifact", payload["evidence"])
        self.assertRegex(payload["evidence"]["hash"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(payload["agent_profile"]["capabilities"]["evidence_redaction"], "redacted")

    def test_dry_run_returns_mapped_payload_without_network(self):
        reporter = CrawlDexReporter(report_url="https://crawldex.com/api/v1/runs", dry_run=True)
        receipt = reporter.report(
            {
                "site": "example.com",
                "task": "subscriptions.cancel",
                "outcome": "blocked",
            }
        )

        self.assertTrue(receipt.accepted)
        self.assertEqual(receipt.acceptance, "dry_run")
        self.assertEqual(receipt.payload["outcome"], "blocked")


if __name__ == "__main__":
    unittest.main()
