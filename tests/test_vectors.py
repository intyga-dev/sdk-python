import hashlib
import json
from pathlib import Path
import unittest

import intyga_sdk

class TestGoldenVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        current_dir = Path(__file__).parent
        vectors_path = current_dir.parent / "vectors" / "canonical-vectors.json"
        with open(vectors_path, "r", encoding="utf-8") as f:
            cls.vectors = json.load(f)

    def test_stable_stringify(self):
        cases = self.vectors.get("stableStringify", [])
        for case in cases:
            name = case["name"]
            val = case["value"]
            expected = case["expected"]
            with self.subTest(name=name):
                result = intyga_sdk.stable_stringify(val)
                self.assertEqual(result, expected)

    def test_intent_payloads(self):
        # The DIV Intent Payload binds target + requester + expiry and is strict RFC 8785 JCS; it must
        # stay byte-identical to the committed vectors (which the TS/Go/Rust builders also pin).
        cases = self.vectors.get("intentPayloads", [])
        self.assertTrue(cases, "no DIV intent vectors present")
        for i, case in enumerate(cases):
            inp = case["input"]
            expected = case["expected"]
            with self.subTest(index=i):
                result = intyga_sdk.canonical_intent_payload(
                    target=inp["target"],
                    action_type=inp["actionType"],
                    display=inp["actionDescription"],
                    params=inp["params"],
                    requester=inp["requester"],
                    requirement=inp["requirement"],
                    nonce=inp["nonce"],
                    expires_at=inp["expiresAt"],
                )
                self.assertEqual(result, expected)

    def test_requester_did_assertion(self):
        # The optional requesterDid assertion must match the receipt's bound requester.
        receipts = {r["name"]: r["receipt"] for r in self.vectors.get("receipts", [])}
        r = receipts["es256-raw-p1363"]
        did = r["requester"]["did"]
        nonce = json.loads(r["canonicalPayload"])["nonce"]

        ok = intyga_sdk.verify_approval_receipt(
            r,
            {
                "target": r["target"],
                "actionType": r["actionType"],
                "params": r["params"],
                "requesterDid": did,
                "nonce": nonce,
                "approvers": {"publicKeys": [r["signerPublicKey"]]},
            },
        )
        self.assertTrue(ok.get("ok"), ok.get("reason"))

        mismatch = intyga_sdk.verify_approval_receipt(
            r,
            {
                "target": r["target"],
                "actionType": r["actionType"],
                "params": r["params"],
                "requesterDid": "did:intyga:someone-else",
                "nonce": nonce,
                "approvers": {"publicKeys": [r["signerPublicKey"]]},
            },
        )
        self.assertFalse(mismatch.get("ok"))

    def test_action_payloads(self):
        cases = self.vectors.get("actionPayloads", [])
        for i, case in enumerate(cases):
            inp = case["input"]
            expected = case["expected"]
            with self.subTest(index=i):
                result = intyga_sdk.canonical_action_payload(
                    nonce=inp["nonce"],
                    action_type=inp["actionType"],
                    summary=inp["summary"],
                    params=inp["params"]
                )
                self.assertEqual(result, expected)

    def test_challenge_payloads(self):
        cases = self.vectors.get("challengePayloads", [])
        for i, case in enumerate(cases):
            inp = case["input"]
            expected = case["expected"]
            with self.subTest(index=i):
                result = intyga_sdk.canonical_challenge_payload(
                    nonce=inp["nonce"],
                    action_description=inp["actionDescription"]
                )
                self.assertEqual(result, expected)

    def test_enroll_payloads(self):
        cases = self.vectors.get("enrollPayloads", [])
        for i, case in enumerate(cases):
            inp = case["input"]
            expected = case["expected"]
            with self.subTest(index=i):
                result = intyga_sdk.canonical_enroll_payload(
                    token=inp["token"],
                    public_key=inp["publicKey"]
                )
                self.assertEqual(result, expected)

    def test_login_payloads(self):
        cases = self.vectors.get("loginPayloads", [])
        for i, case in enumerate(cases):
            inp = case["input"]
            expected = case["expected"]
            with self.subTest(index=i):
                result = intyga_sdk.canonical_login_payload(
                    nonce=inp["nonce"],
                    account_id=inp["accountId"]
                )
                self.assertEqual(result, expected)

    def test_digests(self):
        cases = self.vectors.get("digests", [])
        for i, case in enumerate(cases):
            canonical = case["canonical"]
            digest_hex = case["digestHex"]
            code = case["verificationCode"]
            with self.subTest(index=i):
                self.assertEqual(intyga_sdk.payload_digest_hex(canonical), digest_hex)
                self.assertEqual(intyga_sdk.verification_code(canonical), code)

    def test_receipts(self):
        cases = self.vectors.get("receipts", [])
        for case in cases:
            name = case["name"]
            receipt = case["receipt"]
            expect_ok = case["expectOk"]
            with self.subTest(name=name):
                # The nonce is now part of the expectation: a caller must name the challenge it is
                # redeeming, which is what lets it enforce single-use on its own side. For a golden
                # vector, that is whatever the signed payload commits to.
                # The approver trust anchor is REQUIRED. For a golden vector the committed file is
                # the enrollment record, so pinning its key is the legitimate resolution step — the
                # key still comes from OUTSIDE the code under test.
                expected = {
                    "target": receipt.get("target"),
                    "actionType": receipt.get("actionType"),
                    "params": receipt.get("params"),
                    "nonce": json.loads(receipt["canonicalPayload"])["nonce"],
                    "approvers": {"publicKeys": [receipt.get("signerPublicKey")]}
                    if receipt.get("signerPublicKey")
                    else {"publicKeys": ["unused-for-auto-approved"]},
                }
                res = intyga_sdk.verify_approval_receipt(receipt, expected)
                self.assertEqual(res.get("ok"), expect_ok, f"Failed for {name}: {res.get('reason')}")

    def test_policy_crypto(self):
        policy_data = self.vectors.get("policy", {})
        pub_key = policy_data["rsaPubB64"]
        priv_key = policy_data["rsaPrivB64"]
        plaintext = policy_data["plaintext"]
        blob = policy_data["blob"]

        # 1. Decrypt the golden blob using the golden private key
        decrypted = intyga_sdk.policy.decrypt_policy(priv_key, blob)
        self.assertEqual(decrypted, plaintext)

        # 2. Check blob_hash of the golden blob
        h = intyga_sdk.policy.blob_hash(blob)
        self.assertEqual(h, hashlib.sha256(blob.encode("utf-8")).hexdigest())

        # 3. Key generation
        keys = intyga_sdk.policy.generate_org_keypair()
        self.assertIn("publicKey", keys)
        self.assertIn("privateKey", keys)

        # 4. Encrypt and decrypt a custom message
        custom_msg = "test-policy-123"
        enc_blob = intyga_sdk.policy.encrypt_policy(keys["publicKey"], custom_msg)
        dec_msg = intyga_sdk.policy.decrypt_policy(keys["privateKey"], enc_blob)
        self.assertEqual(dec_msg, custom_msg)

if __name__ == "__main__":
    unittest.main()


class TestTrustAnchor(unittest.TestCase):
    """
    Regression tests for the July 2026 review. Before it, verification used the public key carried
    INSIDE the receipt, which proves only that the receipt is internally consistent.
    """

    def setUp(self):
        vectors_path = (
            Path(__file__).parent.parent.parent / "mcp-schemas" / "vectors" / "canonical-vectors.json"
        )
        with open(vectors_path, "r", encoding="utf-8") as f:
            self.vectors = json.load(f)
        self.receipt = {r["name"]: r["receipt"] for r in self.vectors["receipts"]}["es256-raw-p1363"]
        self.nonce = json.loads(self.receipt["canonicalPayload"])["nonce"]

    def _expected(self, approvers):
        return {
            "target": self.receipt.get("target"),
            "actionType": self.receipt.get("actionType"),
            "params": self.receipt.get("params"),
            "nonce": self.nonce,
            "approvers": approvers,
        }

    def test_missing_anchor_is_refused(self):
        res = intyga_sdk.verify_approval_receipt(
            self.receipt,
            {
                "target": self.receipt.get("target"),
                "actionType": self.receipt.get("actionType"),
                "params": self.receipt.get("params"),
                "nonce": self.nonce,
            },
        )
        self.assertFalse(res.get("ok"))
        self.assertIn("approvers", res.get("reason", ""))

    def test_untrusted_key_is_refused(self):
        # A key that is well-formed and simply not ours.
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from cryptography.hazmat.primitives import serialization as _ser
        import base64 as _b64

        other = _ec.generate_private_key(_ec.SECP256R1())
        spki = other.public_key().public_bytes(
            _ser.Encoding.DER, _ser.PublicFormat.SubjectPublicKeyInfo
        )
        res = intyga_sdk.verify_approval_receipt(
            self.receipt, self._expected({"publicKeys": [_b64.b64encode(spki).decode()]})
        )
        self.assertFalse(res.get("ok"))

    def test_trusted_key_verifies(self):
        res = intyga_sdk.verify_approval_receipt(
            self.receipt, self._expected({"publicKeys": [self.receipt["signerPublicKey"]]})
        )
        self.assertTrue(res.get("ok"), res.get("reason"))

    def test_did_mode_refuses_a_signer_outside_the_allowlist(self):
        res = intyga_sdk.verify_approval_receipt(
            self.receipt,
            self._expected(
                {
                    "dids": ["did:intyga:somebody-else"],
                    "resolveKey": lambda _d: self.receipt["signerPublicKey"],
                }
            ),
        )
        self.assertFalse(res.get("ok"))
        self.assertIn("not an authorized approver", res.get("reason", ""))
