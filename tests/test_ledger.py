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
        self.assertEqual(res["rootSource"], "independent")
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
