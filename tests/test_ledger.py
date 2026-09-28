import json
import unittest
from pathlib import Path

from intyga_sdk import ledger


class TestLedgerVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        current_dir = Path(__file__).parent
        p = current_dir.parent / "vectors" / "ledger-vectors.json"
        with open(p, "r", encoding="utf-8") as f:
            cls.v = json.load(f)

    def test_sha256_and_tags(self):
        for c in self.v["sha256Hex"]:
            self.assertEqual(ledger.sha256_hex(c["input"].encode()), c["expected"])

    def test_hash_leaf(self):
        for c in self.v["hashLeaf"]:
            self.assertEqual(ledger.hash_leaf(c["input"]), c["expected"])

    def test_hash_pair(self):
        for c in self.v["hashPair"]:
            self.assertEqual(ledger.hash_pair(c["left"], c["right"]), c["expected"])

    def test_empty_root(self):
        self.assertEqual(ledger.empty_root(), self.v["emptyRoot"])

    def test_merkle_roots(self):
        for c in self.v["merkleRoots"]:
            with self.subTest(name=c["name"]):
                self.assertEqual(ledger.merkle_root(c["leaves"]), c["expected"])

    def test_leaf_preimage_and_hash(self):
        for c in self.v["leafPreimage"]:
            with self.subTest(name=c["name"]):
                self.assertEqual(ledger.canonical_preimage(c["row"]), c["canonical"])
                self.assertEqual(ledger.leaf_hash(c["row"]), c["leafHash"])

    def test_inclusion_proof(self):
        inc = self.v["inclusion"]
        proof = {
            "leaf": inc["leaf"],
            "blockRoot": inc["blockRoot"],
            "blockProof": inc["blockProof"],
            "leafIndex": inc["leafIndex"],
            "blockLeafCount": inc["blockLeafCount"],
            "checkpointProof": inc["checkpointProof"],
            "checkpointLeafIndex": inc["checkpointLeafIndex"],
            "checkpointLeafCount": inc["checkpointLeafCount"],
            "checkpointRoot": inc["dailyRoot"],
        }
        self.assertTrue(ledger.verify_inclusion_proof(proof, inc["dailyRoot"]))
        # A wrong root must fail.
        self.assertFalse(ledger.verify_inclusion_proof(proof, "0" * 64))
        # A proof that cannot say where its leaf sits does not establish inclusion (§3 invariant 3).
        positionless = {k: v for k, v in proof.items() if k != "leafIndex"}
        self.assertFalse(ledger.verify_inclusion_proof(positionless, inc["dailyRoot"]))

    def test_inclusion_negative_vectors(self):
        """The shared padding-forgery cases every conformant verifier MUST refuse (DEWP §11.1).

        This port previously had no leaf index or leaf count at all, so a path to a leaf slot that
        never existed recomputed the real root and verified.
        """
        cases = self.v["inclusionNegative"]
        self.assertTrue(cases, "ledger-vectors.json carries no inclusionNegative cases")
        for c in cases:
            with self.subTest(name=c["name"]):
                got = ledger.verify_merkle_proof(c["leaf"], c["proof"], c["root"], c["bounds"])
                self.assertEqual(got, c["expected"], c["reason"])

    def test_verify_merkle_proof_refuses_instead_of_crashing_on_missing_bounds(self):
        """`bounds` is REQUIRED (DEWP §3 invariant 3), but Python enforces nothing at the boundary of
        an untyped caller — `None` used to raise AttributeError out of `bounds.get(...)` instead of
        returning a bool."""
        inc = self.v["inclusion"]
        self.assertFalse(ledger.verify_merkle_proof(inc["leaf"], inc["blockProof"], inc["blockRoot"], None))
        self.assertFalse(ledger.verify_merkle_proof(inc["leaf"], inc["blockProof"], inc["blockRoot"], "not-a-dict"))

    def test_anchor_digest(self):
        self.assertEqual(ledger.anchor_digest_hex(self.v["anchor"]["input"]), self.v["anchor"]["digestHex"])

    def test_signed_anchor_vectors(self):
        """The shared §5.2 interop trap: the signed message is the RAW 32-byte anchor digest, never
        its 64-character hex text. A port that signs the hex matches the digest vector and fails
        exactly here — which is the trap's signature, and why every port consumes this section."""
        sa = self.v.get("signedAnchor")
        self.assertTrue(sa and sa.get("cases"), "ledger-vectors.json carries no signedAnchor cases")
        spki = sa["signerKey"]["spkiB64"]
        for c in sa["cases"]:
            with self.subTest(name=c["name"]):
                if c.get("digestHex"):
                    self.assertEqual(ledger.anchor_digest_hex(c["anchor"]), c["digestHex"], c["name"])
                self.assertEqual(
                    ledger.verify_anchor_signature(c["anchor"], spki), c["expectOk"], c["name"]
                )

    def test_verify_anchor_signature_refuses_rather_than_raising(self):
        """A standalone single-anchor ES256 check must stay a predicate for an untyped caller:
        malformed input, a non-ES256 label, or a key of the wrong type is False, never a crash."""
        sa = self.v["signedAnchor"]
        good = sa["cases"][0]["anchor"]
        spki = sa["signerKey"]["spkiB64"]
        self.assertFalse(ledger.verify_anchor_signature(None, spki))
        self.assertFalse(ledger.verify_anchor_signature({}, spki))
        self.assertFalse(ledger.verify_anchor_signature(dict(good, algorithm="Ed25519"), spki))
        self.assertFalse(ledger.verify_anchor_signature(dict(good, signature=""), spki))
        self.assertFalse(ledger.verify_anchor_signature(dict(good, signature="!!not-b64!!"), spki))
        self.assertFalse(ledger.verify_anchor_signature(good, "AAAA"))
        # And the golden anchor still verifies after all that.
        self.assertTrue(ledger.verify_anchor_signature(good, spki))

    def test_verify_bundle_property_model(self):
        inc = self.v["inclusion"]
        bundle = {
            "version": 1,
            "kind": "dewp.audit.inclusion-proof",
            "event": {"canonical": inc["leafRow"]},
            "proof": {
                "leaf": inc["leaf"],
                "blockRoot": inc["blockRoot"],
                "blockProof": inc["blockProof"],
                "leafIndex": inc["leafIndex"],
                "blockLeafCount": inc["blockLeafCount"],
                "checkpointProof": inc["checkpointProof"],
                "checkpointLeafIndex": inc["checkpointLeafIndex"],
                "checkpointLeafCount": inc["checkpointLeafCount"],
                "checkpointRoot": inc["dailyRoot"],
            },
            "anchor": {"dailyRoot": inc["dailyRoot"]},
        }
        # An independently-supplied daily root establishes the COMMITMENT and the CONTENT. It does
        # not establish the ANCHOR: DEWP §3.7 makes anchorVerified conditional on a quorum of
        # distinct trusted issuers signing the same dailyRoot, and this port implements no anchor
        # signature check at all. It used to set anchorVerified purely because a root was passed and
        # report FULLY_VERIFIED off the back of it — a label asserting more than was checked.
        res = ledger.verify_bundle(bundle, trusted_root=inc["dailyRoot"])
        self.assertTrue(res["properties"]["commitmentVerified"])
        self.assertTrue(res["properties"]["contentVerified"])
        self.assertFalse(res["properties"]["anchorVerified"])
        self.assertEqual(res["verificationLevel"], "CONTENT_VERIFIED")
        # The verifier cannot tell where a supplied root came from, so it never calls it "independent".
        self.assertEqual(res["rootSource"], "caller-supplied")
        self.assertTrue(res["ok"])
        self.assertTrue(any("quorum" in n for n in res["notes"]))

        # Without the trusted root the bundle vouches for itself (DEWP §3.6), so it is not ok.
        weak = ledger.verify_bundle(bundle)
        self.assertFalse(weak["properties"]["anchorVerified"])
        self.assertEqual(weak["rootSource"], "self-asserted")
        self.assertFalse(weak["ok"])


if __name__ == "__main__":
    unittest.main()


class ProducerAnchorClaimTest(unittest.TestCase):
    """DEWP §6.2: surface the producer's quorum claim without ever trusting it.

    Reporting the claim and evaluating it are different acts. This port evaluates no quorum, so
    ``anchorVerified`` must stay False whatever the bundle asserts — but a reader comparing two
    exports still needs the claim and the threshold behind it, because a deployment requiring one
    issuer and one requiring three both publish ``externallyAnchored: true``.
    """

    def _bundle(self, **extra):
        leaf = "a" * 64
        bundle = {
            "version": 1,
            "kind": "dewp.audit.inclusion-proof",
            "proof": {
                "leaf": leaf,
                "blockIndex": "0",
                "blockRoot": leaf,
                "blockProof": [],
                "leafIndex": 0,
                "blockLeafCount": 1,
                "checkpointRoot": "b" * 64,
                "checkpointProof": [],
                "checkpointLeafIndex": 0,
                "checkpointLeafCount": 1,
            },
            "event": {},
        }
        bundle.update(extra)
        return bundle

    def test_claim_and_threshold_are_reported(self):
        result = ledger.verify_bundle(self._bundle(externallyAnchored=True, externallyAnchoredRequired=2))
        notes = " ".join(result["notes"])
        self.assertIn("producer CLAIMS external anchoring: True", notes)
        self.assertIn("2 distinct independent issuer(s)", notes)
        self.assertFalse(result["properties"]["anchorVerified"], "a claim is not a check")

    def test_a_claim_without_a_threshold_says_so(self):
        result = ledger.verify_bundle(self._bundle(externallyAnchored=True))
        self.assertIn("an unstated quorum", " ".join(result["notes"]))

    def test_a_bundle_making_no_claim_gets_no_note(self):
        result = ledger.verify_bundle(self._bundle())
        self.assertNotIn("producer CLAIMS", " ".join(result["notes"]))


class BundleRootSelectionTest(unittest.TestCase):
    """DEWP §7.1 root selection, mirroring @intyga/verify's fallback chain.

    Python stopped at ``anchor.dailyRoot``, but the reference producer omits ``anchor`` entirely
    until signed anchors exist (`apps/web/app/api/audit/proof/[seq]/route.ts`). The ordinary console
    export therefore reported ``INVALID`` — the verdict that reads as "forged" — for an untampered
    bundle that @intyga/verify reports as self-asserted and CONTENT_VERIFIED.
    """

    @classmethod
    def setUpClass(cls):
        current_dir = Path(__file__).parent
        p = current_dir.parent / "vectors" / "ledger-vectors.json"
        with open(p, "r", encoding="utf-8") as f:
            cls.v = json.load(f)

    def _bundle(self, **over):
        inc = self.v["inclusion"]
        bundle = {
            "version": 1,
            "kind": ledger.BUNDLE_KIND,
            "event": {"canonical": inc["leafRow"]},
            "proof": {
                "leaf": inc["leaf"],
                "blockRoot": inc["blockRoot"],
                "blockProof": inc["blockProof"],
                "leafIndex": inc["leafIndex"],
                "blockLeafCount": inc["blockLeafCount"],
                "checkpointProof": inc["checkpointProof"],
                "checkpointLeafIndex": inc["checkpointLeafIndex"],
                "checkpointLeafCount": inc["checkpointLeafCount"],
                "checkpointRoot": inc["dailyRoot"],
            },
        }
        bundle.update(over)
        return bundle

    def test_no_anchor_key_falls_back_to_the_proofs_own_checkpoint_root(self):
        res = ledger.verify_bundle(self._bundle())
        self.assertEqual(res["rootSource"], "self-asserted")
        self.assertTrue(res["properties"]["commitmentVerified"])
        self.assertEqual(res["verificationLevel"], "CONTENT_VERIFIED")
        # Self-asserted is still not a verdict (DEWP §3.6), so it must not be ok.
        self.assertFalse(res["ok"])

    def test_legacy_anchor_is_read_before_the_proof_root(self):
        res = ledger.verify_bundle(
            self._bundle(legacyAnchor={"dailyRoot": self.v["inclusion"]["dailyRoot"]})
        )
        self.assertEqual(res["rootSource"], "self-asserted")
        self.assertTrue(res["properties"]["commitmentVerified"])

    def test_a_bundle_with_no_root_anywhere_still_reports_none(self):
        b = self._bundle()
        del b["proof"]["checkpointRoot"]
        res = ledger.verify_bundle(b)
        self.assertEqual(res["rootSource"], "none")
        self.assertEqual(res["verificationLevel"], "INVALID")


class RedactedBundleTest(unittest.TestCase):
    """DEWP §15: a COMMITMENT_ONLY entry retains the leaf and ships no preimage.

    ``ok`` required contentVerified, which requires a leaf binding, which a redacted export cannot
    supply — so a lawfully redacted bundle was rejected here and accepted by @intyga/verify.
    """

    @classmethod
    def setUpClass(cls):
        current_dir = Path(__file__).parent
        p = current_dir.parent / "vectors" / "ledger-vectors.json"
        with open(p, "r", encoding="utf-8") as f:
            cls.v = json.load(f)

    def _bundle(self, **over):
        inc = self.v["inclusion"]
        bundle = {
            "version": 1,
            "kind": ledger.BUNDLE_KIND,
            "event": {"canonical": inc["leafRow"]},
            "proof": {
                "leaf": inc["leaf"],
                "blockRoot": inc["blockRoot"],
                "blockProof": inc["blockProof"],
                "leafIndex": inc["leafIndex"],
                "blockLeafCount": inc["blockLeafCount"],
                "checkpointProof": inc["checkpointProof"],
                "checkpointLeafIndex": inc["checkpointLeafIndex"],
                "checkpointLeafCount": inc["checkpointLeafCount"],
                "checkpointRoot": inc["dailyRoot"],
            },
        }
        bundle.update(over)
        return bundle

    def test_a_redacted_entry_stays_ok_at_commitment_verified(self):
        b = self._bundle(event={})
        res = ledger.verify_bundle(b, trusted_root=self.v["inclusion"]["dailyRoot"])
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["verificationLevel"], "COMMITMENT_VERIFIED")
        self.assertTrue(res["properties"]["commitmentVerified"])
        self.assertFalse(res["properties"]["contentVerified"])
        self.assertIsNone(res["checks"]["leafBinding"])

    def test_an_unknown_profile_over_a_shipped_preimage_is_still_not_ok(self):
        # The security case the redaction allowance must not open: a prover-supplied `profile` must
        # never switch leaf binding off for content the bundle DID ship.
        res = ledger.verify_bundle(
            self._bundle(profile="someone.else.v9"),
            trusted_root=self.v["inclusion"]["dailyRoot"],
        )
        self.assertFalse(res["ok"])
        self.assertIsNone(res["checks"]["leafBinding"])

    def test_a_mismatched_leaf_is_still_not_ok(self):
        res = ledger.verify_bundle(
            self._bundle(event={"canonical": dict(self.v["inclusion"]["leafRow"], detail="tampered")}),
            trusted_root=self.v["inclusion"]["dailyRoot"],
        )
        self.assertFalse(res["ok"])
        self.assertFalse(res["checks"]["leafBinding"])


class InclusionProofPredicateTest(unittest.TestCase):
    """``verify_inclusion_proof`` is a documented public primitive, so malformed input is False.

    It indexed ``proof["leaf"]`` and ``proof["blockRoot"]`` directly, so a relying party calling it
    outside ``verify_bundle``'s try/except got a KeyError — and a caller treating an exception as
    anything other than a refusal fails open.
    """

    def test_malformed_proofs_return_false_rather_than_raising(self):
        for name, proof in {
            "no leaf": {"blockRoot": "a" * 64},
            "no blockRoot": {"leaf": "a" * 64},
            "empty": {},
            "not a dict": None,
            "blockProof is not a list": {"leaf": "a" * 64, "blockRoot": "a" * 64, "blockProof": "x"},
        }.items():
            with self.subTest(name):
                self.assertFalse(ledger.verify_inclusion_proof(proof, "b" * 64))


class AnchorSignatureAlphabetTest(unittest.TestCase):
    """DEWP §5.2 admits anchors from issuers the producer does not control, so the encoding of a
    key or signature is not ours to assume. ``base64.b64decode`` without ``validate`` silently
    DISCARDS ``-`` and ``_`` rather than erroring, so a base64url-encoded anchor decoded to
    different bytes here and read as an invalid signature on input @intyga/verify accepts."""

    @classmethod
    def setUpClass(cls):
        current_dir = Path(__file__).parent
        p = current_dir.parent / "vectors" / "ledger-vectors.json"
        with open(p, "r", encoding="utf-8") as f:
            cls.v = json.load(f)

    @staticmethod
    def _to_b64url(s: str) -> str:
        return s.replace("+", "-").replace("/", "_").rstrip("=")

    def test_base64url_key_and_signature_verify_identically(self):
        sa = self.v["signedAnchor"]
        anchor = sa["cases"][0]["anchor"]
        spki = sa["signerKey"]["spkiB64"]
        self.assertTrue(ledger.verify_anchor_signature(anchor, spki))
        url_anchor = dict(anchor, signature=self._to_b64url(anchor["signature"]))
        self.assertTrue(ledger.verify_anchor_signature(url_anchor, self._to_b64url(spki)))
