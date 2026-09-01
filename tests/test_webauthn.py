"""Pins the §4.4.5 WebAuthn verification path against the shared golden vector.

This path previously had zero test coverage in this package — the vector was consumed by the Go,
Rust and Java suites only. The vector's assertion fields are unpadded base64url (the DIV §4.4.2
wire form the gateway emits), so this also pins the flexible decoding that accepts it.
"""

import json
from pathlib import Path
import unittest

import intyga_sdk


class TestWebAuthnVector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        current_dir = Path(__file__).parent
        p = current_dir.parent / "vectors" / "webauthn-vector.json"
        with open(p, "r", encoding="utf-8") as f:
            cls.v = json.load(f)

    def _expected(self):
        v = self.v
        return {
            "target": v["expected"]["target"],
            "actionType": v["expected"]["actionType"],
            "params": v["expected"]["params"],
            "nonce": v["expected"]["nonce"],
            "approvers": {"publicKeys": [v["receipt"]["signerPublicKey"]]},
        }

    def test_golden_webauthn_receipt_verifies(self):
        v = self.v
        res = intyga_sdk.verify_approval_receipt(
            v["receipt"],
            self._expected(),
            expected_origin=v["origin"],
            expected_rp_id=v["rpId"],
        )
        self.assertTrue(res["ok"], res)

    def test_fails_closed_without_pinning(self):
        # Origin and RP ID are the only things binding the assertion to THIS relying party.
        res = intyga_sdk.verify_approval_receipt(self.v["receipt"], self._expected())
        self.assertFalse(res["ok"])

    def test_wrong_origin_is_refused(self):
        v = self.v
        res = intyga_sdk.verify_approval_receipt(
            v["receipt"],
            self._expected(),
            expected_origin="https://evil.example.com",
            expected_rp_id=v["rpId"],
        )
        self.assertFalse(res["ok"])

    def test_wrong_rp_id_is_refused(self):
        v = self.v
        res = intyga_sdk.verify_approval_receipt(
            v["receipt"],
            self._expected(),
            expected_origin=v["origin"],
            expected_rp_id="evil.example.com",
        )
        self.assertFalse(res["ok"])

    def test_tampered_params_are_refused(self):
        v = self.v
        expected = self._expected()
        expected["params"] = {**expected["params"], "amount": 999999}
        res = intyga_sdk.verify_approval_receipt(
            v["receipt"],
            expected,
            expected_origin=v["origin"],
            expected_rp_id=v["rpId"],
        )
        self.assertFalse(res["ok"])

    def test_untrusted_key_is_refused(self):
        # A receipt checked against a key that is not in the caller's trust anchor must fail —
        # the witness's own signerPublicKey is never the trust anchor (DIV Invariant 3).
        v = self.v
        expected = self._expected()
        expected["approvers"] = {"publicKeys": ["AAAA" + v["receipt"]["signerPublicKey"][4:]]}
        res = intyga_sdk.verify_approval_receipt(
            v["receipt"],
            expected,
            expected_origin=v["origin"],
            expected_rp_id=v["rpId"],
        )
        self.assertFalse(res["ok"])


if __name__ == "__main__":
    unittest.main()
