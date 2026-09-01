"""Regression pins for fail-closed behavior in the untyped entry points.

Each of these once passed open: `expected` without a target bound the receipt to target "",
`expected` without a nonce let a payload carrying a literal null nonce through (None == None),
and a bundle with an ABSENT `kind` skipped the DEWP §6.5 gate entirely. All three were found by
the Aug 2026 conformance audit; the TS reference refuses each one.
"""

import json
from pathlib import Path
import unittest

import intyga_sdk
from intyga_sdk import ledger


def _first_verifying_case(vectors):
    """The first receipts case the suite expects to verify (`expectOk` true)."""
    for case in vectors.get("receipts", []):
        if case.get("expectOk"):
            return case
    raise AssertionError("no verifying receipts case in canonical-vectors.json")


class TestApprovalReceiptFailClosed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        current_dir = Path(__file__).parent
        vectors_path = current_dir.parent / "vectors" / "canonical-vectors.json"
        with open(vectors_path, "r", encoding="utf-8") as f:
            cls.vectors = json.load(f)
        receipt = _first_verifying_case(cls.vectors)["receipt"]
        cls.receipt = receipt
        # Same expectation shape test_vectors.py builds: for a golden vector the committed file is
        # the enrollment record, so pinning its key is the legitimate resolution step.
        cls.expected = {
            "approvers": {"publicKeys": [receipt["signerPublicKey"]]},
            "target": receipt.get("target", ""),
            "actionType": receipt.get("actionType", ""),
            "params": receipt.get("params", {}),
            "nonce": json.loads(receipt["canonicalPayload"])["nonce"],
        }

    def test_golden_case_still_verifies_with_full_expectation(self):
        res = intyga_sdk.verify_approval_receipt(self.receipt, dict(self.expected))
        self.assertTrue(res["ok"], res)

    def test_missing_expected_target_is_refused(self):
        expected = dict(self.expected)
        del expected["target"]
        res = intyga_sdk.verify_approval_receipt(self.receipt, expected)
        self.assertFalse(res["ok"])
        self.assertIn("Target Isolation", res["reason"])

    def test_empty_expected_target_is_refused(self):
        expected = dict(self.expected)
        expected["target"] = ""
        res = intyga_sdk.verify_approval_receipt(self.receipt, expected)
        self.assertFalse(res["ok"])
        self.assertIn("Target Isolation", res["reason"])

    def test_missing_expected_nonce_is_refused(self):
        expected = dict(self.expected)
        del expected["nonce"]
        res = intyga_sdk.verify_approval_receipt(self.receipt, expected)
        self.assertFalse(res["ok"])
        self.assertIn("expected['nonce']", res["reason"])

    def test_missing_expected_action_type_is_refused(self):
        # DIV §4.4.1: actionType is a security-binding field. It used to default to "", so a receipt
        # minted over an empty actionType verified against an expectation that never named the
        # action — ok:True with no binding at all.
        expected = dict(self.expected)
        del expected["actionType"]
        res = intyga_sdk.verify_approval_receipt(self.receipt, expected)
        self.assertFalse(res["ok"])
        self.assertIn("expected['actionType']", res["reason"])

    def test_missing_expected_params_is_refused(self):
        expected = dict(self.expected)
        del expected["params"]
        res = intyga_sdk.verify_approval_receipt(self.receipt, expected)
        self.assertFalse(res["ok"])
        self.assertIn("expected['params']", res["reason"])

    def test_explicitly_empty_binding_fields_are_still_accepted(self):
        # Only OMISSION is refused. A caller who genuinely executes a parameterless action writes
        # {} and must keep verifying, or the guard would break a legitimate shape.
        expected = dict(self.expected)
        expected["actionType"] = ""
        expected["params"] = {}
        res = intyga_sdk.verify_approval_receipt(self.receipt, expected)
        self.assertFalse(res["ok"])
        self.assertIn("do not match what was approved", res["reason"])

    def test_none_expected_nonce_is_refused(self):
        # The historical hole: a payload carrying a literal `"nonce": null` compared equal to an
        # absent expected nonce (None == None). The guard must fire on the expectation alone.
        expected = dict(self.expected)
        expected["nonce"] = None
        res = intyga_sdk.verify_approval_receipt(self.receipt, expected)
        self.assertFalse(res["ok"])
        self.assertIn("expected['nonce']", res["reason"])


class TestBundleKindFailClosed(unittest.TestCase):
    def test_absent_kind_is_refused(self):
        # DEWP §6.5 + the authoritative inclusion-proof schema make `kind` required; a bundle
        # without one must be INVALID, not quietly verified.
        res = ledger.verify_bundle({"proof": {}, "event": {}})
        self.assertFalse(res["ok"])
        self.assertEqual(res["verificationLevel"], "INVALID")
        self.assertTrue(any("§6.5" in n for n in res["notes"]), res["notes"])

    def test_wrong_kind_is_still_refused(self):
        res = ledger.verify_bundle({"kind": "vendor.other", "proof": {}, "event": {}})
        self.assertFalse(res["ok"])
        self.assertEqual(res["verificationLevel"], "INVALID")
        self.assertTrue(any("§6.5" in n for n in res["notes"]), res["notes"])


class TestDelegationKeySetRefusal(unittest.TestCase):
    def test_delegation_refuses_key_set_anchor_at_seal_verification(self):
        # DIV §4.4.6: the sealing quorum names PEOPLE; a key-set anchor counts credentials and can
        # never associate identities, so seal verification must refuse it outright.
        payload = {
            "v": 1,
            "type": "div-delegation",
            "delegatedTo": ["did:intyga:op-1"],
            "delegatedQuorum": 1,
            "sealedAt": "2999-01-01T00:00:00.000Z",
            "expiresAt": "2999-01-01T01:00:00.000Z",
            "requirement": {
                "requiredApprovals": 1,
                "requireHardwareKey": False,
                "allowedAaguids": [],
                "requesterCannotApprove": False,
                "signerClass": "human",
            },
            "target": "t",
            "actionType": "x",
            "params": {},
        }
        receipt = {
            "canonicalPayload": json.dumps(payload),
            "actionDescription": "d",
            "params": {},
            "requester": {"did": "did:intyga:agent-x", "attestation": None},
        }
        res = intyga_sdk.verify_delegation(
            receipt,
            {"approvers": {"publicKeys": ["k"]}, "target": "t", "actionType": "x", "params": {}},
        )
        self.assertFalse(res["ok"])
        self.assertIn("§4.4.6", res["reason"])

    def test_delegation_refuses_an_omitted_binding_field(self):
        # Same DIV §4.4.1 default as the approval verifier had: actionType/params fell back to
        # ""/{} here too, so a delegation could be rebuilt bound to nothing.
        payload = {
            "v": 1,
            "type": "div-delegation",
            "delegatedTo": ["did:intyga:op-1"],
            "delegatedQuorum": 1,
            "sealedAt": "2020-01-01T00:00:00.000Z",
            "expiresAt": "2020-01-01T01:00:00.000Z",
            "requirement": {
                "requiredApprovals": 1,
                "requireHardwareKey": False,
                "allowedAaguids": [],
                "requesterCannotApprove": False,
                "signerClass": "human",
            },
            "target": "t",
            "actionType": "x",
            "params": {},
        }
        receipt = {
            "canonicalPayload": json.dumps(payload),
            "actionDescription": "d",
            "params": {},
            "requester": {"did": "did:intyga:agent-x", "attestation": None},
        }
        res = intyga_sdk.verify_delegation(
            receipt,
            {"approvers": {"dids": ["did:intyga:alice"]}, "target": "t", "params": {}},
        )
        self.assertFalse(res["ok"])
        self.assertIn("expected['actionType']", res["reason"])


if __name__ == "__main__":
    unittest.main()
