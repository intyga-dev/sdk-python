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
            "checkpointProof": inc["checkpointProof"],
            "checkpointRoot": inc["dailyRoot"],
        }
        self.assertTrue(ledger.verify_inclusion_proof(proof, inc["dailyRoot"]))
        # A wrong root must fail.
        self.assertFalse(ledger.verify_inclusion_proof(proof, "0" * 64))

    def test_anchor_digest(self):
        self.assertEqual(ledger.anchor_digest_hex(self.v["anchor"]["input"]), self.v["anchor"]["digestHex"])

    def test_verify_bundle_property_model(self):
        inc = self.v["inclusion"]
        bundle = {
            "kind": "dewp.audit.inclusion-proof",
            "event": {"canonical": inc["leafRow"]},
            "proof": {
                "leaf": inc["leaf"],
                "blockRoot": inc["blockRoot"],
                "blockProof": inc["blockProof"],
                "checkpointProof": inc["checkpointProof"],
                "checkpointRoot": inc["dailyRoot"],
            },
            "anchor": {"dailyRoot": inc["dailyRoot"]},
        }
        # With the independently-supplied daily root, an unsigned event is FULLY_VERIFIED.
        res = ledger.verify_bundle(bundle, trusted_root=inc["dailyRoot"])
        self.assertTrue(res["properties"]["commitmentVerified"])
        self.assertTrue(res["properties"]["contentVerified"])
        self.assertTrue(res["properties"]["anchorVerified"])
        self.assertEqual(res["verificationLevel"], "FULLY_VERIFIED")
        # Without the trusted root: internally consistent but not anchor-verified.
        weak = ledger.verify_bundle(bundle)
        self.assertFalse(weak["properties"]["anchorVerified"])
        self.assertEqual(weak["verificationLevel"], "CONTENT_VERIFIED")


if __name__ == "__main__":
    unittest.main()
