import unittest

from crawldex_report import canonical_json, hash_evidence_artifact, redact_evidence_artifact


class RedactionTests(unittest.TestCase):
    def test_hash_uses_deterministic_canonical_json(self):
        first = hash_evidence_artifact({"b": [2, {"d": 4, "c": 3}], "a": 1})
        second = hash_evidence_artifact({"a": 1, "b": [2, {"c": 3, "d": 4}]})

        self.assertEqual(first, second)
        self.assertEqual(canonical_json({"b": 2, "a": 1}), '{"a":1,"b":2}')

    def test_redacts_query_strings_email_tokens_and_sensitive_fields(self):
        redacted = redact_evidence_artifact(
            {
                "url": "https://example.com/cancel?token=abc123&email=person@example.com#frag",
                "note": "Contact person@example.com with Bearer abcdefghijklmnop or token=secret-value",
                "authorization": "Bearer private-token",
                "screenshots": ["base64-data"],
            }
        )

        artifact = redacted["artifact"]
        self.assertEqual(artifact["url"], "https://example.com/cancel")
        self.assertNotIn("person@example.com", artifact["note"])
        self.assertNotIn("secret-value", artifact["note"])
        self.assertEqual(artifact["authorization"], "[redacted]")
        self.assertEqual(artifact["screenshots"], "[redacted]")
        self.assertIn("$.authorization", redacted["removed_fields"])
        self.assertIn("$.screenshots", redacted["removed_fields"])


if __name__ == "__main__":
    unittest.main()
