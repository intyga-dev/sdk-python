"""DEWP audit-ledger verification (docs/DEWP.md) — Python port.

Byte-identical to the TypeScript reference (`@intyga/verify` ledger-*.ts) and the Go/Rust ports,
locked by the shared cross-language vectors (packages/mcp-schemas/vectors/ledger-vectors.json).

Domain separation: 0x00 leaf, 0x01 node, 0x02 empty root, 0x03 anchor. Node children are HEX-DECODED
to raw bytes before hashing; the anchor signature covers the raw 32-byte digest.
"""

import hashlib
import json
from typing import Any, Dict, List, Optional

LEAF_TAG = b"\x00"
NODE_TAG = b"\x01"
EMPTY_TAG = b"\x02"
ANCHOR_TAG = b"\x03"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_leaf(preimage: str) -> str:
    """Domain-separated leaf digest: sha256(0x00 || UTF8(preimage))."""
    return sha256_hex(LEAF_TAG + preimage.encode("utf-8"))


def hash_pair(left_hex: str, right_hex: str) -> str:
    """Domain-separated node: sha256(0x01 || rawBytes(left) || rawBytes(right)). Order matters."""
    return sha256_hex(NODE_TAG + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


def empty_root() -> str:
    """Empty-tree root (DEWP §5.1.1): sha256(0x02)."""
    return sha256_hex(EMPTY_TAG)


def merkle_root(leaves: List[str]) -> str:
    if len(leaves) == 0:
        return empty_root()
    level = list(leaves)
    while len(level) > 1:
        nxt: List[str] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left  # duplicate-last
            nxt.append(hash_pair(left, right))
        level = nxt
    return level[0]


def verify_merkle_proof(leaf: str, proof: List[Dict[str, str]], root: str) -> bool:
    """Recompute the root from a leaf + its (leaf→root) proof. Each step: {siblingHash, siblingPosition}."""
    h = leaf
    for step in proof:
        if step.get("siblingPosition") == "LEFT":
            h = hash_pair(step["siblingHash"], h)
        else:
            h = hash_pair(h, step["siblingHash"])
    return h == root


# ── Leaf preimage (DEWP intyga.v1 profile: 18-element array, tenantSeq last) ───────────────────────
# Order MUST match packages/verify ledger-leaf.ts and the producer. metadata is embedded as a plain
# JSON string (insertion order, not JCS) exactly like JS `JSON.stringify(metadata ?? null)`.
def canonical_preimage(row: Dict[str, Any]) -> str:
    metadata = row.get("metadata", None)
    # DEWP §4.2: metadata is a JCS string — keys sorted recursively (sort_keys), so the leaf hash is
    # insertion-order- and language-independent. Matches @intyga/verify jcsStringify.
    metadata_str = (
        json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if metadata is not None
        else "null"
    )
    arr = [
        row.get("seq"),
        row.get("createdAt"),
        row.get("event"),
        row.get("outcome"),
        row.get("detail"),
        metadata_str,
        row.get("signerDid"),
        row.get("signerPublicKey"),
        row.get("signedPayload"),
        row.get("signature"),
        row.get("sigAlg"),
        bool(row.get("isBillable", False)),
        row.get("tenantId"),
        row.get("actorNodeId"),
        row.get("subjectNodeId"),
        row.get("edgeId"),
        row.get("challengeId"),
        row.get("tenantSeq"),
    ]
    return json.dumps(arr, separators=(",", ":"), ensure_ascii=False)


def leaf_hash(row: Dict[str, Any]) -> str:
    return hash_leaf(canonical_preimage(row))


def verify_inclusion_proof(proof: Dict[str, Any], daily_root: str) -> bool:
    """Two-hop DEWP proof: leaf → block root, then hashLeaf(block root) → daily root."""
    if not verify_merkle_proof(proof["leaf"], proof.get("blockProof", []), proof["blockRoot"]):
        return False
    return verify_merkle_proof(hash_leaf(proof["blockRoot"]), proof.get("checkpointProof", []), daily_root)


# ── Signed anchors (DEWP §5.2) ────────────────────────────────────────────────────────────────────
def anchor_preimage(anchor: Dict[str, str]) -> str:
    """JCS of [dailyRoot, timestamp, issuer, algorithm] — for string arrays this is compact JSON."""
    return json.dumps(
        [anchor["dailyRoot"], anchor["timestamp"], anchor["issuer"], anchor["algorithm"]],
        separators=(",", ":"),
        ensure_ascii=False,
    )


def anchor_digest_hex(anchor: Dict[str, str]) -> str:
    """Raw 32-byte anchor digest (hex): sha256(0x03 || UTF8(anchor_preimage))."""
    return sha256_hex(ANCHOR_TAG + anchor_preimage(anchor).encode("utf-8"))


# ── Bundle verification with the DEWP §7.1 property model ─────────────────────────────────────────
def verify_bundle(bundle: Dict[str, Any], trusted_root: Optional[str] = None) -> Dict[str, Any]:
    """Verify a single inclusion-proof bundle. Returns the four independent properties + summary level.

    `trusted_root` is the daily root obtained from an external anchor; without it, anchorVerified is
    false (the bundle's own root is self-asserted and not a trustworthy verdict).
    """
    proof = bundle["proof"]
    event = bundle.get("event", {})
    canonical = event.get("canonical")

    if trusted_root is not None:
        daily_root = trusted_root
        root_source = "independent"
    elif bundle.get("anchor", {}).get("dailyRoot"):
        daily_root = bundle["anchor"]["dailyRoot"]
        root_source = "self-asserted"
    else:
        daily_root = None
        root_source = "none"

    inclusion_ok = daily_root is not None and verify_inclusion_proof(proof, daily_root)
    root_consistency = daily_root is not None and proof.get("checkpointRoot") == daily_root
    commitment_verified = bool(inclusion_ok and root_consistency)

    leaf_binding = canonical is not None and leaf_hash(canonical) == proof["leaf"]
    content_verified = bool(commitment_verified and leaf_binding)

    anchor_verified = bool(commitment_verified and root_source == "independent")

    # signatureVerified would re-verify the embedded DIV ES256 signature; kept out of the core port to
    # avoid a crypto dependency here (the TS verifier does it). Reported false unless content fails.
    signature_verified = False

    properties = {
        "commitmentVerified": commitment_verified,
        "contentVerified": content_verified,
        "signatureVerified": signature_verified,
        "anchorVerified": anchor_verified,
    }
    has_signer = bool(canonical and canonical.get("signature") and canonical.get("signerPublicKey"))
    if not commitment_verified:
        level = "INVALID"
    elif not content_verified:
        level = "COMMITMENT_VERIFIED"
    elif anchor_verified and (signature_verified or not has_signer):
        level = "FULLY_VERIFIED"
    elif signature_verified:
        level = "SIGNATURE_VERIFIED"
    else:
        level = "CONTENT_VERIFIED"

    return {
        "ok": commitment_verified and content_verified and root_source == "independent",
        "rootSource": root_source,
        "properties": properties,
        "verificationLevel": level,
    }
