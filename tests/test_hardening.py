"""Regression tests for the sdk-python security audit findings.

Each test names the failure it locks out. None of these paths had any coverage: `tests/` never
exercised IntygaClient at all, and the vector suites only ever fed the verifiers well-formed input.
"""

import asyncio
import json
import sys
import unittest
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from intyga_sdk import ledger  # noqa: E402
from intyga_sdk.client import IntygaClient  # noqa: E402
from intyga_sdk.crypto import (  # noqa: E402
    MAX_REPORTED_FAILURES,
    MAX_WITNESSES,
    NonCanonicalValue,
    canonical_delegation_payload,
    canonical_intent_payload,
    stable_stringify,
    verify_approval_receipt,
    verify_delegation,
)

REQUESTER = {"did": "did:intyga:agent:test", "attestation": None}
REQUIREMENT = {
    "requiredApprovals": 1,
    "requireHardwareKey": False,
    "allowedAaguids": [],
    "requesterCannotApprove": False,
    "signerClass": "human",
}
EXPECTED = {
    "target": "t",
    "nonce": "n",
    "actionType": "a",
    "params": {},
    "approvers": {"publicKeys": ["AAAA"]},
}


class TestParameterBinding(unittest.TestCase):
    """DIV §3 Invariant 1. stable_stringify used to `return "null"` for anything json.dumps refused,
    collapsing distinct parameter sets to identical signed bytes."""

    def test_non_json_values_are_refused_not_coerced_to_null(self):
        for value in [Decimal("1.00"), {1, 2}, b"bytes", object()]:
            with self.assertRaises(NonCanonicalValue, msg=f"{value!r} was silently canonicalized"):
                stable_stringify(value)

    def test_two_different_amounts_cannot_produce_the_same_signed_bytes(self):
        # The collision that made this critical: Decimal is the idiomatic Python type for money, and
        # both amounts became `"amount":null`. A relying party recomputing the payload accepted a
        # receipt a human had approved for a different figure.
        def build(amount):
            return canonical_intent_payload(
                "t", "wire", "d", {"amount": amount, "to": "alice"},
                REQUESTER, REQUIREMENT, "n", "2026-01-01T00:00:00Z",
            )

        with self.assertRaises(NonCanonicalValue):
            build(Decimal("1.00"))
        # The portable equivalents still work and stay distinct.
        self.assertNotEqual(build(1.0), build(9999999.0))

    def test_non_portable_numbers_are_refused(self):
        # Outside this range Python's repr and JS Number#toString disagree, so the two ports would
        # sign different bytes for the same value (DIV §4.1).
        for value in [1e21, 1e16, 1e-7, -0.0, float("nan"), float("inf")]:
            with self.assertRaises(NonCanonicalValue, msg=f"{value!r} should be refused"):
                stable_stringify(value)

    def test_an_int_above_the_double_range_is_a_refusal_not_an_OverflowError(self):
        # `math.isnan` converts to double first, so an arbitrary-precision int raised OverflowError
        # out of the public signing APIs instead of the documented NonCanonicalValue contract.
        with self.assertRaises(NonCanonicalValue):
            stable_stringify({"a": 10 ** 400})
        with self.assertRaises(NonCanonicalValue):
            stable_stringify(-(10 ** 400))

    def test_portable_numbers_still_work(self):
        self.assertEqual(stable_stringify(0.5), "0.5")
        self.assertEqual(stable_stringify(9007199254740991), "9007199254740991")
        self.assertEqual(stable_stringify(1.0), "1")


class TestHostileInputReturnsVerdict(unittest.TestCase):
    """Inv. 10. `requester` and `requirement` are read from attacker-controlled JSON before any byte
    comparison, so these were all reachable pre-authentication. A traceback is not a refusal."""

    def _receipt(self, **over):
        base = {
            "canonicalPayload": json.dumps({"v": 1, "type": "div-intent-verification"}),
            "sigAlg": "ES256",
        }
        base.update(over)
        return base

    def test_malformed_receipt_shapes_return_ok_false(self):
        cases = {
            "requester as string": self._receipt(requester="hax"),
            "requester as list": self._receipt(requester=[1, 2]),
            "signatures as strings": self._receipt(signatures=["x", "y"]),
            "receipt is None": None,
            "receipt is a string": "nope",
            "receipt is a list": [1, 2, 3],
        }
        for name, receipt in cases.items():
            with self.subTest(name):
                result = verify_approval_receipt(receipt, EXPECTED)
                self.assertFalse(result["ok"])
                self.assertIn("reason", result)

    def test_deep_nesting_returns_a_verdict_rather_than_RecursionError(self):
        deep = current = {}
        for _ in range(6000):
            current["a"] = {}
            current = current["a"]
        result = verify_approval_receipt(self._receipt(requester=deep), EXPECTED)
        self.assertFalse(result["ok"])

    def test_reason_never_carries_an_exception_traceback(self):
        # Python prints locals in traceback frames, and those frames hold key material here.
        result = verify_approval_receipt(self._receipt(requester="hax"), EXPECTED)
        self.assertNotIn("Traceback", result["reason"])


class TestWitnessCap(unittest.TestCase):
    """Inv. 10. Every witness costs an ECDSA verification and the list is attacker-supplied:
    20,000 measured at ~1.5s CPU and a 1.16 MB reason string, per request, from a JSON body."""

    def test_witness_list_above_the_cap_is_refused_before_verification(self):
        # The payload must match `expected` exactly, otherwise the receipt is rejected on the nonce
        # or target long before the witness loop — which would make this test pass for the wrong
        # reason and prove nothing about the cap.
        from datetime import datetime, timedelta, timezone

        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        canonical = canonical_intent_payload(
            "t", "a", "d", {}, REQUESTER, REQUIREMENT, "n", expires,
        )
        receipt = {
            "canonicalPayload": canonical,
            "sigAlg": "ES256",
            "requester": REQUESTER,
            # The verifier rebuilds `display` from actionDescription (DIV §3.2: reconstruct locally),
            # so it must match the payload or the receipt is refused before the witness loop.
            "actionDescription": "d",
            "signatures": [
                {"signerDid": f"did:x:{i}", "signature": "AA", "publicKey": "BB", "sigAlg": "ES256"}
                for i in range(MAX_WITNESSES + 1)
            ],
        }
        result = verify_approval_receipt(receipt, EXPECTED)
        self.assertFalse(result["ok"])
        self.assertIn("above the maximum", result["reason"])

    def test_a_quorum_sized_witness_list_still_reaches_verification(self):
        # The cap must not become the reason a legitimate multi-signature receipt is refused.
        from datetime import datetime, timedelta, timezone

        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        canonical = canonical_intent_payload(
            "t", "a", "d", {}, REQUESTER, REQUIREMENT, "n", expires,
        )
        receipt = {
            "canonicalPayload": canonical,
            "sigAlg": "ES256",
            "requester": REQUESTER,
            # The verifier rebuilds `display` from actionDescription (DIV §3.2: reconstruct locally),
            # so it must match the payload or the receipt is refused before the witness loop.
            "actionDescription": "d",
            "signatures": [
                {"signerDid": f"did:x:{i}", "signature": "AA", "publicKey": "BB"} for i in range(3)
            ],
        }
        result = verify_approval_receipt(receipt, EXPECTED)
        self.assertFalse(result["ok"])  # the signatures are junk, so it still fails
        self.assertNotIn("above the maximum", result["reason"])  # but not because of the cap


class TestDelegationWitnessCap(unittest.TestCase):
    """Inv. 10. verify_delegation runs the same attacker-supplied witness loop as
    verify_approval_receipt but shipped without its MAX_WITNESSES cap, so a delegation body was the
    one remaining route to per-request ECDSA amplification."""

    def _delegation_receipt(self, witness_count):
        # Everything above the witness loop must pass, otherwise the delegation is refused on the
        # window, quorum shape, or byte comparison first — which would make these tests pass for the
        # wrong reason and prove nothing about the cap.
        from datetime import datetime, timedelta, timezone

        sealed = datetime.now(timezone.utc)
        sealed_at = sealed.isoformat().replace("+00:00", "Z")
        expires_at = (sealed + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        canonical = canonical_delegation_payload(
            "t", "a", "d", {}, REQUESTER, REQUIREMENT,
            ["did:op:one", "did:op:two"], 1, "n", sealed_at, expires_at,
        )
        return {
            "canonicalPayload": canonical,
            "sigAlg": "ES256",
            "requester": REQUESTER,
            # The verifier rebuilds `display` from actionDescription (DIV §3.2: reconstruct locally),
            # so it must match the payload or the receipt is refused before the witness loop.
            "actionDescription": "d",
            "signatures": [
                {"signerDid": f"did:x:{i}", "signature": "AA", "publicKey": "BB", "sigAlg": "ES256"}
                for i in range(witness_count)
            ],
        }

    # DID mode: delegations refuse a key-set anchor outright (DIV §4.4.6), and these tests are
    # about the witness cap and reason folding, which must still be reached. The allowlist covers
    # every junk witness DID so each one fails at SIGNATURE verification, as the fold test counts.
    DELEGATION_EXPECTED = {
        **EXPECTED,
        "approvers": {
            "dids": [f"did:x:{i}" for i in range(MAX_WITNESSES + 1)],
            "resolveKey": lambda did: "AAAA",
        },
    }

    def test_witness_list_above_the_cap_is_refused_before_verification(self):
        result = verify_delegation(self._delegation_receipt(MAX_WITNESSES + 1), self.DELEGATION_EXPECTED)
        self.assertFalse(result["ok"])
        self.assertIn("above the maximum", result["reason"])

    def test_a_quorum_sized_witness_list_still_reaches_verification(self):
        # The cap must not become the reason a legitimate multi-signature delegation is refused.
        result = verify_delegation(self._delegation_receipt(3), self.DELEGATION_EXPECTED)
        self.assertFalse(result["ok"])  # the signatures are junk, so it still fails
        self.assertNotIn("above the maximum", result["reason"])  # but not because of the cap

    def test_failure_reasons_are_folded_not_joined_unbounded(self):
        # An unbounded join over the witness list was itself the memory half of the amplification.
        result = verify_delegation(
            self._delegation_receipt(MAX_REPORTED_FAILURES + 4), self.DELEGATION_EXPECTED
        )
        self.assertFalse(result["ok"])
        self.assertIn("+4 more", result["reason"])
        self.assertEqual(result["reason"].count("signature does not verify"), MAX_REPORTED_FAILURES)


class TestBundleVerification(unittest.TestCase):
    def _bundle(self, **over):
        b = {"kind": ledger.BUNDLE_KIND, "proof": {"leaf": "a" * 64}}
        b.update(over)
        return b

    def test_malformed_bundles_return_INVALID_rather_than_raising(self):
        cases = {
            "no proof": {},
            "proof is a string": {"proof": "x"},
            "canonical is a string": {"proof": {"leaf": "a"}, "event": {"canonical": "zz"}},
            "anchor is None": {"proof": {"leaf": "a"}, "anchor": None},
            "bundle is None": None,
        }
        for name, bundle in cases.items():
            with self.subTest(name):
                result = ledger.verify_bundle(bundle)
                self.assertFalse(result["ok"])
                self.assertEqual(result["verificationLevel"], "INVALID")

    def test_non_canonical_kind_is_rejected(self):
        # DEWP §6.5: an evidence-bundle carries a different completeness guarantee, so returning a
        # verdict on one under inclusion-proof rules vouches for something never checked.
        result = ledger.verify_bundle(self._bundle(kind="dewp.audit.evidence-bundle"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["verificationLevel"], "INVALID")

    def test_unknown_profile_does_not_get_a_clean_verdict(self):
        # DEWP §4.5. Reporting a leaf mismatch here would read as tampering; the honest answer is
        # "unknown layout, not attempted".
        result = ledger.verify_bundle(self._bundle(profile="someone.else.v9"))
        self.assertFalse(result["ok"])
        self.assertIsNone(result["checks"]["leafBinding"])


class TestJcsMetadataOrdering(unittest.TestCase):
    """DEWP §4.1. json.dumps(sort_keys=True) orders by code POINT; JCS requires UTF-16 code UNIT.
    They disagree for every character above the BMP, and no ledger vector contains one."""

    def test_astral_keys_sort_by_utf16_code_unit(self):
        preimage = ledger.canonical_preimage({"metadata": {"": 2, "\U0001F600": 1}})
        emoji_at = preimage.index("\U0001F600")
        pua_at = preimage.index("")
        self.assertLess(emoji_at, pua_at, "astral key must sort first, as it does in JS")

    def test_nested_metadata_is_sorted_at_every_depth(self):
        preimage = ledger.canonical_preimage({"metadata": {"outer": {"b": 1, "a": 2}}})
        self.assertIn('{\\"a\\":2,\\"b\\":1}', preimage)


class TestJcsMetadataNumberFormatting(unittest.TestCase):
    """DEWP §4.2. Number TEXT is part of the hashed bytes, and `json.dumps` alone diverges from the
    TS reference (`JSON.stringify` semantics) for whole-valued floats: runtime-built metadata with
    100.0 serialized as "100.0" where the producer wrote "100" — same event, different leaf hash,
    reported as tampering. The residual (values outside the portable range, e.g. 0.00001 -> "1e-05"
    here vs "0.00001" in JS) is deliberately a fail-to-match, not a refusal — the TS ledger jcs has
    no portability guard and a verifier must never crash on a leaf it cannot reproduce."""

    def test_whole_valued_float_folds_to_integer_text(self):
        # JS has one number type: JSON.stringify({amount: 100.0}) is '{"amount":100}'.
        preimage = ledger.canonical_preimage({"metadata": {"amount": 100.0, "rate": 0.5}})
        self.assertIn('{\\"amount\\":100,\\"rate\\":0.5}', preimage)

    def test_float_and_integer_metadata_hash_to_the_same_leaf(self):
        # The TS bytes are what the producer committed; a Python verifier handed the same values as
        # floats (any JSON round-trip does this) must recompute the identical leaf hash.
        self.assertEqual(
            ledger.canonical_preimage({"metadata": {"amount": 100.0}}),
            ledger.canonical_preimage({"metadata": {"amount": 100}}),
        )
        self.assertEqual(
            ledger.leaf_hash({"metadata": {"amount": 100.0}}),
            ledger.leaf_hash({"metadata": {"amount": 100}}),
        )


class TestClientTargetBinding(unittest.TestCase):
    """DIV §3 Invariant 5. All four language ports omitted `target`: consume 400'd so redemption was
    unreachable, and authorize let the gateway default to the literal "global"."""

    def test_authorize_refuses_without_a_target(self):
        client = IntygaClient("https://gw.example", token="t")
        with self.assertRaises(ValueError):
            asyncio.run(client.authorize("wire", action_type="wire"))

    def test_consume_refuses_without_a_target(self):
        client = IntygaClient("https://gw.example", token="t")
        with self.assertRaises(ValueError):
            asyncio.run(client.consume("n_1", "wire"))

    def test_target_from_the_constructor_is_accepted(self):
        client = IntygaClient("https://gw.example", token="t", target="prod-payments")
        self.assertEqual(client._resolve_target(None), "prod-payments")
        self.assertEqual(client._resolve_target("override"), "override")

    def test_blank_target_is_refused(self):
        client = IntygaClient("https://gw.example", token="t")
        for blank in ["", "   "]:
            with self.assertRaises(ValueError):
                client._resolve_target(blank)


class TestAmbientCredentials(unittest.TestCase):
    """Inv. 6/7. Reading ~/.intyga/credentials.json unconditionally meant a service built with no
    credentials silently assumed whatever principal `intyga login` had left in that home directory."""

    def test_stored_credentials_are_off_by_default(self):
        client = IntygaClient("https://gw.example")
        self.assertFalse(client._allow_stored_credentials)
        with self.assertRaises(ValueError):
            asyncio.run(client.token())

    def test_stored_credentials_can_be_opted_into(self):
        client = IntygaClient("https://gw.example", allow_stored_credentials=True)
        self.assertTrue(client._allow_stored_credentials)


if __name__ == "__main__":
    unittest.main()


class TestSignerClassRegistry(unittest.TestCase):
    """DIV §4.3.2 / §5-step-3a: the signerClass registry fails closed. An unrecognized class must
    never verify as if it were human-approved, and a payload with no class predates the field and
    cannot be verified by this version."""

    def _receipt_with_class(self, signer_class):
        from datetime import datetime, timedelta, timezone

        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        requirement = dict(REQUIREMENT)
        if signer_class is None:
            del requirement["signerClass"]
        else:
            requirement["signerClass"] = signer_class
        canonical = canonical_intent_payload(
            "t", "a", "d", {}, REQUESTER, requirement, "n", expires,
        )
        # The builder defaults a MISSING signerClass to "" in the bytes; strip it so the payload is
        # genuinely pre-signerClass, as a stale producer would have emitted it.
        if signer_class is None:
            canonical = canonical.replace(',"signerClass":""', "")
        return {
            "canonicalPayload": canonical,
            "sigAlg": "ES256",
            "requester": REQUESTER,
            "actionDescription": "d",
            "signatures": [{"signerDid": "did:x:1", "signature": "AA", "publicKey": "BB"}],
        }

    def test_unrecognized_class_is_refused_not_treated_as_human(self):
        result = verify_approval_receipt(self._receipt_with_class("delegated-agent"), EXPECTED)
        self.assertFalse(result["ok"])
        self.assertIn("does not recognize", result["reason"])
        self.assertIn("delegated-agent", result["reason"])

    def test_missing_class_is_refused(self):
        result = verify_approval_receipt(self._receipt_with_class(None), EXPECTED)
        self.assertFalse(result["ok"])
        self.assertIn("missing signerClass", result["reason"])

    def test_human_class_reaches_signature_verification(self):
        # "human" must pass the registry gate: the junk signature is then the failure, not the class.
        result = verify_approval_receipt(self._receipt_with_class("human"), EXPECTED)
        self.assertFalse(result["ok"])
        self.assertNotIn("signerClass", result["reason"])
