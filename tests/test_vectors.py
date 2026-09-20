import hashlib
import json
from datetime import datetime
from pathlib import Path
import unittest

import intyga_sdk


def _did_anchor(approvers):
    """DID-mode trust anchor from the vector's identity → keys table (multi-key per identity).

    Mirrors `didAnchor` in packages/verify/src/vectors.test.ts: every key returned for a DID counts
    as that ONE approver, which is what the distinct-identity quorum cases pin.
    """
    keys = {a["did"]: a["keys"] for a in approvers}
    return {"dids": list(keys), "resolveKey": lambda did: keys.get(did)}


def _as_of(name, case):
    """A case's committed evaluation time (DIV §5a.3 rule 3).

    Raises rather than defaulting to the wall clock: a missing `asOf` would silently restore the
    position-blind behaviour these vectors exist to pin against.
    """
    raw = case.get("asOf")
    if not isinstance(raw, str) or not raw:
        raise AssertionError(f"{name}: vector carries no usable asOf")
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def _expectation_for(receipt, approvers):
    """The expectation a relying party would assert, rebuilt from the receipt's echoes.

    The nonce comes from the signed canonical payload — for a golden vector, that is the challenge
    the relying party is redeeming (mirrors `expectationFor` in the TS consumer).
    """
    return {
        "approvers": approvers,
        "target": receipt.get("target", ""),
        "actionType": receipt.get("actionType", ""),
        "params": receipt.get("params", {}),
        "nonce": json.loads(receipt["canonicalPayload"])["nonce"],
    }


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

    def test_agent_intent_payloads(self):
        for case in self.vectors.get("agentIntentPayloads", []):
            inp = case["input"]
            self.assertEqual(intyga_sdk.canonical_intent_payload(
                target=inp["target"], action_type=inp["actionType"],
                display=inp["actionDescription"], params=inp["params"],
                requester=inp["requester"], requirement=inp["requirement"],
                nonce=inp["nonce"], expires_at=inp["expiresAt"],
                agent_context=inp["agentContext"],
            ), case["expected"])

    def test_offline_intent_payloads(self):
        # Offline approval shares the intent payload's canonicalization contract and adds
        # `challengedAt`. The two kinds must never produce the same bytes: if they did, an out-of-band
        # approval would be indistinguishable from a gateway-mediated one, and an ordinary approval
        # could be replayed as an offline one long after the fact.
        cases = self.vectors.get("offlineIntentPayloads", [])
        self.assertTrue(cases, "no offline-approval vectors present")
        for i, case in enumerate(cases):
            inp = case["input"]
            with self.subTest(index=i):
                result = intyga_sdk.canonical_offline_intent_payload(
                    target=inp["target"],
                    action_type=inp["actionType"],
                    display=inp["actionDescription"],
                    params=inp["params"],
                    requester=inp["requester"],
                    requirement=inp["requirement"],
                    nonce=inp["nonce"],
                    challenged_at=inp["challengedAt"],
                    expires_at=inp["expiresAt"],
                )
                self.assertEqual(result, case["expected"])
                self.assertIn('"type":"div-offline-intent"', result)

                # And the kinds must not collide for the same action.
                intent = intyga_sdk.canonical_intent_payload(
                    target=inp["target"],
                    action_type=inp["actionType"],
                    display=inp["actionDescription"],
                    params=inp["params"],
                    requester=inp["requester"],
                    requirement=inp["requirement"],
                    nonce=inp["nonce"],
                    expires_at=inp["expiresAt"],
                )
                self.assertNotEqual(result, intent)

    def test_delegation_payloads(self):
        # A delegation authorizes nothing, so what these pin is that its bytes are distinct from both
        # other kinds and that `delegatedTo` is canonicalized as a SET. The vector input is
        # deliberately unsorted, so this is what proves every port sorts it.
        cases = self.vectors.get("delegationPayloads", [])
        self.assertTrue(cases, "no delegation vectors present")
        for i, case in enumerate(cases):
            inp = case["input"]
            with self.subTest(index=i):
                result = intyga_sdk.canonical_delegation_payload(
                    target=inp["target"],
                    action_type=inp["actionType"],
                    display=inp["actionDescription"],
                    params=inp["params"],
                    requester=inp["requester"],
                    requirement=inp["requirement"],
                    delegated_to=inp["delegatedTo"],
                    delegated_quorum=inp["delegatedQuorum"],
                    nonce=inp["nonce"],
                    sealed_at=inp["sealedAt"],
                    expires_at=inp["expiresAt"],
                )
                self.assertEqual(result, case["expected"])
                self.assertIn('"type":"div-delegation"', result)
                self.assertIn(
                    # UTF-16 code-unit order: U+1F600 before U+FFFD, where Python's default
                    # code-point sort puts it after. This pins the comparator, not just "sorted".
                    '"delegatedTo":["did:intyga:sre-a","did:intyga:sre-c","did:intyga:sre-😀","did:intyga:sre-�"]',
                    result,
                )

    def test_delegation_is_refused_by_the_approval_verifier(self):
        # The structural guarantee: a delegation must never be accepted as an approval, and there is no
        # option that would let one through.
        case = self.vectors["delegationPayloads"][0]
        receipt = {
            "canonicalPayload": case["expected"],
            "actionDescription": case["input"]["actionDescription"],
            "params": case["input"]["params"],
            "requester": case["input"]["requester"],
            "verificationCode": "0000-0000",
        }
        expected = {
            "target": case["input"]["target"],
            "actionType": case["input"]["actionType"],
            "params": case["input"]["params"],
            "nonce": case["input"]["nonce"],
            "approvers": {"publicKeys": ["x"]},
        }
        for kwargs in (
            {},
            {"allow_offline": True},
            {"allow_offline": True, "allow_auto_approved": True, "allow_expired": True},
        ):
            r = intyga_sdk.verify_approval_receipt(receipt, expected, **kwargs)
            self.assertFalse(r.get("ok"))
            self.assertIn("authorizes no action on its own", r.get("reason", ""))

    def test_offline_proof_is_refused_without_the_opt_in(self):
        case = self.vectors["offlineIntentPayloads"][0]
        receipt = {
            "canonicalPayload": case["expected"],
            "actionDescription": case["input"]["actionDescription"],
            "params": case["input"]["params"],
            "requester": case["input"]["requester"],
            "verificationCode": "0000-0000",
        }
        expected = {
            "target": case["input"]["target"],
            "actionType": case["input"]["actionType"],
            "params": case["input"]["params"],
            "nonce": case["input"]["nonce"],
            "approvers": {"publicKeys": ["x"]},
        }
        r = intyga_sdk.verify_approval_receipt(receipt, expected)
        self.assertFalse(r.get("ok"))
        self.assertIn("allow_offline", r.get("reason", ""))

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
                # Pinning the REASON, not just the refusal: `0 >= 0` makes DIV §5 step 7 true with
                # nothing counted, so this receipt can be refused for the right rule or for none.
                if name == "zero-required-approvals-refused":
                    self.assertIn(
                        "requiredApprovals must be an integer of at least 1", res.get("reason", "")
                    )

    # ── Shared receipt-level vectors: quorum / offline / delegation ───────────────────────────────
    # Mirrors packages/verify/src/vectors.test.ts. NOTE: canonical-vectors.json also carries a
    # `documentPayloads` section whose own `note` marks it TS-only (document signing is a
    # gateway-side ceremony, apps/gateway/src/integrity.ts, not part of the relying-party offline
    # surface the Go/Rust/Python ports implement) — this port deliberately has no consumer or
    # builder for it, same as Go and Rust.

    def test_quorum_receipts(self):
        # Quorum counts distinct approver IDENTITIES, never signature entries: one approver
        # deliberately holds TWO enrolled keys, and two signatures under them are still one approval.
        # Same cases the TS consumer pins (packages/verify/src/vectors.test.ts).
        section = self.vectors.get("quorumReceipts")
        self.assertTrue(section and section.get("cases"), "no quorum receipt vectors present")
        anchor = _did_anchor(section["approvers"])
        for case in section["cases"]:
            with self.subTest(name=case["name"]):
                r = intyga_sdk.verify_approval_receipt(
                    case["receipt"], _expectation_for(case["receipt"], anchor)
                )
                self.assertEqual(
                    r.get("ok"), case["expectOk"], f"{case['name']}: {r.get('reason', '(ok)')}"
                )
                if case.get("expectSigners"):
                    # A SET expectation — order is not part of the contract.
                    self.assertEqual(
                        sorted(r.get("signers", [])), sorted(case["expectSigners"]), case["name"]
                    )
                if not case["expectOk"] and case.get("expectReasonIncludes"):
                    self.assertIn(case["expectReasonIncludes"], r.get("reason", ""), case["name"])

    def test_offline_receipts(self):
        # Pins the opt-in refusal and the 60-minute window cap: an offline proof is refused without
        # allow_offline, and one whose signed window exceeds the cap fails even WITH the opt-in —
        # validly signed, so what fails is the bound, not the signature.
        cases = self.vectors.get("offlineReceipts", [])
        self.assertTrue(cases, "no offline receipt vectors present")
        approvers = {"publicKeys": [self.vectors["signerKey"]["spkiB64"]]}
        for case in cases:
            receipt = case["receipt"]
            expected = _expectation_for(receipt, approvers)
            with self.subTest(name=case["name"]):
                as_of = _as_of(case["name"], case)
                with_opt_in = intyga_sdk.verify_approval_receipt(
                    receipt, expected, allow_offline=True, as_of=as_of
                )
                self.assertEqual(
                    with_opt_in.get("ok"),
                    case["expectOkWithOptIn"],
                    f"{case['name']}: {with_opt_in.get('reason', '(ok)')}",
                )
                if case.get("refusedWithoutOptIn"):
                    without = intyga_sdk.verify_approval_receipt(receipt, expected, as_of=as_of)
                    self.assertFalse(
                        without.get("ok"),
                        f"{case['name']} must be refused without the offline opt-in",
                    )
                # The forward-dating rule sits outside allow_expired's reach: that override
                # re-examines a proof that WAS valid and has lapsed, never one dated ahead.
                if case["name"] == "offline-forward-dated-refused":
                    audit = intyga_sdk.verify_approval_receipt(
                        receipt, expected, allow_offline=True, allow_expired=True, as_of=as_of
                    )
                    self.assertFalse(audit.get("ok"), case["name"])
                    self.assertIn("challenged in the future", audit.get("reason", ""))

    def test_delegation_receipts(self):
        # Pins the sealing quorum and the 72-hour window cap. The positive case's verdict must carry
        # the (sorted, deduplicated) delegatedTo set and the delegated quorum — that dict is what a
        # caller later passes as delegation= to verify_approval_receipt, so its shape is contract.
        section = self.vectors.get("delegationReceipts")
        self.assertTrue(section and section.get("cases"), "no delegation receipt vectors present")
        anchor = _did_anchor(section["approvers"])
        for case in section["cases"]:
            receipt = case["receipt"]
            with self.subTest(name=case["name"]):
                r = intyga_sdk.verify_delegation(
                    receipt,
                    {
                        "approvers": anchor,
                        "target": receipt.get("target", ""),
                        "actionType": receipt.get("actionType", ""),
                        "params": receipt.get("params", {}),
                    },
                    as_of=_as_of(case["name"], case),
                )
                self.assertEqual(
                    r.get("ok"), case["expectOk"], f"{case['name']}: {r.get('reason', '(ok)')}"
                )
                if case["expectOk"]:
                    self.assertEqual(r["delegation"]["delegatedTo"], case["delegatedTo"])
                    self.assertEqual(r["delegation"]["delegatedQuorum"], case["delegatedQuorum"])

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
        # EXACTLY this expression, matching the other setUp methods in this file:
        # scripts/build-public-tree.sh rewrites `current_dir.parent.parent / "mcp-schemas" /
        # "vectors"` to the vendored repo-local path when assembling the public sdk-python repo.
        # This class previously spelled the same path as Path(__file__).parent.parent.parent —
        # the sed missed it, and these four tests shipped failing in the public tree.
        current_dir = Path(__file__).parent
        vectors_path = current_dir.parent / "vectors" / "canonical-vectors.json"
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

    def test_cached_delegation_expiry_is_rechecked_when_used(self):
        case = self.vectors["offlineReceipts"][0]
        receipt = case["receipt"]
        payload = json.loads(receipt["canonicalPayload"])
        signer_did = receipt["signerDid"]
        expected = {
            "target": payload["target"], "actionType": payload["actionType"],
            "params": payload["params"], "nonce": payload["nonce"],
            "approvers": {"dids": [signer_did], "resolveKey": lambda did: receipt["signerPublicKey"]},
        }
        delegation = {
            "target": payload["target"], "actionType": payload["actionType"], "params": payload["params"],
            "delegatedTo": [signer_did], "delegatedQuorum": 1, "expiresAt": "2998-12-31T23:59:00Z",
        }
        verify = lambda at, **kw: intyga_sdk.verify_approval_receipt(
            receipt, expected, allow_offline=True, delegation=delegation,
            as_of=datetime.fromisoformat(at.replace("Z", "+00:00")), **kw)
        self.assertTrue(verify("2998-12-31T23:58:59Z")["ok"])
        self.assertTrue(verify("2998-12-31T23:59:30Z")["ok"])
        expired = verify("2998-12-31T23:59:31Z")
        self.assertFalse(expired["ok"])
        self.assertIn("delegation has expired", expired["reason"])
        self.assertTrue(intyga_sdk.verify_approval_receipt(receipt, expected, allow_offline=True,
            as_of=datetime.fromisoformat("2998-12-31T23:59:31+00:00"))["ok"])
        self.assertTrue(verify("2998-12-31T23:59:31Z", allow_expired=True)["ok"])
        delegation["expiresAt"] = "invalid"
        self.assertFalse(verify("2998-12-31T23:58:59Z", allow_expired=True)["ok"])

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
