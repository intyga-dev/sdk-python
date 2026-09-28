"""2026-09-27 review L15, L17, L19 and I7. Cross-language verdicts live in the parity vectors."""
import unittest

from intyga_sdk import crypto


class TestInputHardening(unittest.TestCase):
    def test_signed_times_follow_one_strict_rfc3339_grammar(self):
        for ok in ("2027-09-01T12:00:00Z", "2027-09-01T12:00:00.123456789Z",
                   "2027-09-01T14:00:00+02:00", "2028-02-29T00:00:00-23:59"):
            self.assertIsNotNone(crypto._parse_rfc3339(ok), ok)
        self.assertEqual(crypto._parse_rfc3339("2027-09-01T14:00:00+02:00"),
                         crypto._parse_rfc3339("2027-09-01T12:00:00Z"))
        for bad in ("2027-09-01", "2027-09-01T12:00:00", "2027-09-01 12:00:00Z", "2027-09-01t12:00:00z",
                    "2027-02-30T12:00:00Z", "2027-02-29T12:00:00Z", "2027-06-30T23:59:60Z",
                    "2027-09-01T12:00:00,5Z", "2027-09-01T12:00:00.1234567891Z", "2027-09-01T12:00:00+24:00",
                    "+02027-09-01T12:00:00Z", "2027-09-01T12:00Z", None, 20270901):
            self.assertIsNone(crypto._parse_rfc3339(bad), bad)

    def test_canonicalization_refuses_unpaired_surrogates(self):
        for bad in ("\ud800", "a\udc00", "\udbff!"):
            with self.assertRaises(crypto.NonCanonicalValue):
                crypto.stable_stringify({"k": bad})
            with self.assertRaises(crypto.NonCanonicalValue):
                crypto.stable_stringify({bad: 1})
        self.assertEqual(crypto.stable_stringify({"e": "\U0001F600"}), '{"e":"\U0001F600"}')

    def test_a_key_shared_by_two_dids_counts_once(self):
        counted = {}
        self.assertIsNone(crypto._shared_key_problem(counted, "AAEC", "did:a"))
        self.assertIsNone(crypto._shared_key_problem(counted, "AAEC", "did:a"))
        self.assertIsNotNone(crypto._shared_key_problem(counted, "AAEC", "did:b"))
        self.assertIsNone(crypto._shared_key_problem(counted, "AAE=", "did:c"))
        self.assertIsNotNone(crypto._shared_key_problem(counted, "AAE", "did:d"))

    def test_an_empty_trust_anchor_refuses_without_raising(self):
        result = crypto.verify_approval_receipt(
            {"canonicalPayload": "{}"}, {"approvers": {}, "target": "t", "nonce": "n"})
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
