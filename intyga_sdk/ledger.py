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

#: The only bundle shape this verifier implements (DEWP §6.5). An evidence-bundle or an
#: evidence-stream carries different semantics and a different completeness guarantee, so returning a
#: verdict on one under inclusion-proof rules would vouch for something never checked.
BUNDLE_KIND = "dewp.audit.inclusion-proof"

#: The Application Profile whose leaf layout `canonical_preimage` reproduces (DEWP §4.5). A bundle
#: declaring another profile has a preimage this port cannot rebuild — the honest answer is "unknown
#: layout", not a leaf mismatch that reads as tampering.
AUDIT_PROFILE = "trust.intyga.audit.v1"


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


def expected_path_length(leaf_count: int) -> int:
    """Audit-path length for a duplicate-last tree of leaf_count leaves: ceil(log2(n)), 0 when n <= 1."""
    if leaf_count <= 1:
        return 0
    n = 0
    size = leaf_count
    while size > 1:
        size = (size + 1) // 2
        n += 1
    return n


def _is_hash64(s: Any) -> bool:
    """Exactly 64 lowercase hex characters (DEWP §4.4)."""
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def verify_merkle_proof(
    leaf: str, proof: List[Dict[str, str]], root: str, bounds: Dict[str, int]
) -> bool:
    """Recompute the root from a leaf + its (leaf→root) proof, bounded by the leaf's position.

    Each step: {siblingHash, siblingPosition}. `bounds` is {"index", "leafCount"} and is REQUIRED
    (DEWP §3 invariant 3: "The bounds are REQUIRED, not advisory").

    Bounds are what make this a proof of MEMBERSHIP rather than a proof that A path exists. This tree
    pads an unpaired trailing node by hashing it against ITSELF, so merkle_root([a,b,c]) equals
    merkle_root([a,b,c,c]) and a path built for the nonexistent index 3 recomputes the 3-leaf root
    exactly. DEWP §11.1 states outright that an implementation stopping at root recomputation is
    non-conformant — this port did exactly that.
    """
    if not _is_hash64(leaf) or not _is_hash64(root):
        return False
    # `bounds` is REQUIRED (see above), but Python enforces nothing at the boundary of an untyped
    # caller — `bounds.get(...)` on `None` would raise AttributeError instead of returning a bool.
    # Refusing here keeps this a predicate for that caller instead of a crash.
    if not isinstance(bounds, dict):
        return False
    index = bounds.get("index")
    leaf_count = bounds.get("leafCount")
    if not isinstance(index, int) or not isinstance(leaf_count, int):
        return False
    if isinstance(index, bool) or isinstance(leaf_count, bool):
        return False
    if leaf_count < 1 or index < 0 or index >= leaf_count:
        return False
    if len(proof) != expected_path_length(leaf_count):
        return False

    idx = index
    level_size = leaf_count
    node = leaf
    for step in proof:
        sibling = step.get("siblingHash")
        if not _is_hash64(sibling):
            return False
        # The side follows from the index; a prover-chosen side would restore the flexibility the
        # length check just removed.
        expected_side = "LEFT" if idx % 2 == 1 else "RIGHT"
        if step.get("siblingPosition") != expected_side:
            return False
        # Self-pairing is legitimate ONLY at the unpaired end of an odd-sized level. Anywhere else it
        # is the signature of an index pointing into padding — the check that actually closes the
        # forgery, since leafCount arrives inside the proof and a prover can inflate it.
        self_paired = sibling == node
        legitimately_unpaired = idx == level_size - 1 and level_size % 2 == 1
        if self_paired and not legitimately_unpaired:
            return False
        node = hash_pair(sibling, node) if expected_side == "LEFT" else hash_pair(node, sibling)
        idx //= 2
        level_size = (level_size + 1) // 2
    return node == root


# ── Leaf preimage (DEWP intyga.v1 profile: 18-element array, tenantSeq last) ───────────────────────
# Order MUST match packages/verify ledger-leaf.ts and the producer. metadata is embedded as a JCS
# string (DEWP §4.2, normative): keys sorted recursively by UTF-16 code unit, number text as JS
# `JSON.stringify` emits it — matching @intyga/verify's `jcsStringify`.
def _jcs(value: Any) -> str:
    """RFC 8785 JCS serialization — keys sorted by UTF-16 code unit at every depth.

    `json.dumps(..., sort_keys=True)` is NOT this. Python sorts `str` by Unicode CODE POINT, while
    JCS (and therefore `@intyga/verify`'s `jcsStringify`, which uses `Object.keys().sort()`) orders by
    UTF-16 CODE UNIT. The two disagree for every character above the BMP: an astral key such as
    U+1F600 sorts AFTER U+E000 by code point but BEFORE it by code unit, because its surrogate pair
    begins 0xD83D.

    A leaf whose metadata mixes an astral key with one in U+E000..U+FFFF therefore hashed differently
    here than at the producer, and `verify_bundle` reported a leaf mismatch — content-mismatch, which
    is indistinguishable from tampering — for a genuine, untampered event. `crypto.py` already had the
    right comparator; this path did not reuse it, and at the time no ledger vector contained a
    non-BMP character, so the golden-vector gate could not catch it (the `metadata-utf16-key-order`
    vector now pins this).
    """
    if isinstance(value, dict):
        parts = [
            f"{json.dumps(k, ensure_ascii=False)}:{_jcs(value[k])}"
            for k in sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))
        ]
        return "{" + ",".join(parts) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs(v) for v in value) + "]"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # Number TEXT is part of the hashed bytes, and `json.dumps` alone diverges from JS for
        # whole-valued floats: a runtime-built metadata value of 100.0 serialized as "100.0" where
        # the TS producer wrote "100" — same event, different leaf hash, reported as tampering.
        # Reuse the canonical formatter from crypto.py rather than a second copy of the rule.
        # Imported lazily so this module stays hashlib-only at import time (see verify_bundle).
        #
        # KNOWN RESIDUAL: outside the portable range (1e-4 <= |x| < 1e16) Python's repr and JS
        # still disagree (0.00001 -> "1e-05" here, "0.00001" in JS). Deliberately NOT refused: the
        # TS reference jcs has no portability guard, and a verifier must fail-to-match on such a
        # leaf rather than crash. Producers that need the guarantee validate at signing time
        # (stable_stringify refuses non-portable numbers).
        from .crypto import format_jcs_number

        return format_jcs_number(value)
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def canonical_preimage(row: Dict[str, Any]) -> str:
    metadata = row.get("metadata", None)
    # DEWP §4.2: metadata is a JCS string — keys sorted recursively, so the leaf hash is
    # insertion-order- and language-independent. Matches @intyga/verify jcsStringify.
    metadata_str = _jcs(metadata) if metadata is not None else "null"
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
    """Two-hop DEWP proof: leaf → block root, then hashLeaf(block root) → daily root.

    Each hop is bounded by its position (DEWP §3 invariant 3, steps 1 and 2). A proof that cannot say
    where its leaf sits does not establish inclusion, so missing position fields are a rejection.
    """
    if not verify_merkle_proof(
        proof["leaf"],
        proof.get("blockProof", []),
        proof["blockRoot"],
        {"index": proof.get("leafIndex"), "leafCount": proof.get("blockLeafCount")},
    ):
        return False
    return verify_merkle_proof(
        hash_leaf(proof["blockRoot"]),
        proof.get("checkpointProof", []),
        daily_root,
        {
            "index": proof.get("checkpointLeafIndex"),
            "leafCount": proof.get("checkpointLeafCount"),
        },
    )


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


def verify_anchor_signature(anchor: Dict[str, Any], public_key_spki_b64: str) -> bool:
    """Verify ONE anchor's ES256 signature over its raw 32-byte digest (DEWP §5.2).

    A standalone single-anchor primitive, and exactly that: NOT quorum verification (§5.3), and
    deliberately not wired into ``verify_bundle`` — ``anchor_verified`` there is conditional on a
    quorum of distinct trusted issuers (§3.7), which this port does not implement, so it stays
    ``False`` regardless of what this function returns.

    The signed MESSAGE is the raw 32-byte anchor digest, never its 64-character hex text. ECDSA
    P-256/SHA-256 hashes the message again internally (so no Prehashed): an implementation that
    signs the hex matches the digest vector and still fails to interoperate — the §5.2 trap the
    shared ``signedAnchor`` vectors exist to catch. The signature is base64 DER (the TS producer
    signs with dsaEncoding "der"); raw 64-byte IEEE-P1363 is also accepted, exactly as in
    ``crypto.verify_ecdsa_p256``.

    ``public_key_spki_b64`` (base64 DER SPKI) comes from the CALLER's trust policy, never from the
    anchor itself. The key is pinned to EC P-256 so an anchor labelled ES256 cannot be verified
    under some other scheme, and any escape is a refusal — a verifier that raises has not returned
    "invalid", it has crashed.
    """
    try:
        if not isinstance(anchor, dict) or anchor.get("algorithm") != "ES256":
            return False
        signature_b64 = anchor.get("signature")
        if not isinstance(signature_b64, str) or not signature_b64:
            return False

        # Imported here, not at module top: bundle verification deliberately needs only hashlib,
        # and this primitive is the one place the ledger module touches real crypto.
        import base64

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        public_key = serialization.load_der_public_key(base64.b64decode(public_key_spki_b64))
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        if not isinstance(public_key.curve, ec.SECP256R1):
            return False

        digest = bytes.fromhex(anchor_digest_hex(anchor))
        signature = base64.b64decode(signature_b64)

        # Raw IEEE-P1363 (r||s) is always exactly 64 bytes for P-256; DER can in principle also be
        # 64, so length is not a reliable discriminator — try both encodings rather than inferring.
        candidates = []
        if len(signature) == 64:
            r = int.from_bytes(signature[:32], byteorder="big")
            s = int.from_bytes(signature[32:], byteorder="big")
            candidates.append(encode_dss_signature(r, s))
        candidates.append(signature)
        for candidate in candidates:
            try:
                public_key.verify(candidate, digest, ec.ECDSA(hashes.SHA256()))
                return True
            except Exception:
                continue
        return False
    except Exception:
        return False


# ── Bundle verification with the DEWP §7.1 property model ─────────────────────────────────────────
def verify_bundle(bundle: Dict[str, Any], trusted_root: Optional[str] = None) -> Dict[str, Any]:
    """Verify a single inclusion-proof bundle. Returns the four independent properties + summary level.

    `trusted_root` is the daily root obtained from an external anchor; without it, anchorVerified is
    false (the bundle's own root is self-asserted and not a trustworthy verdict).
    """
    notes: List[str] = []

    # Every field below comes from an untrusted artifact. Shape-check before use: a verifier that
    # raises on a malformed bundle has not returned "invalid", it has crashed, and a caller that
    # treats an exception as anything other than a refusal fails open.
    if not isinstance(bundle, dict):
        return _invalid("bundle is not an object")
    proof = bundle.get("proof")
    if not isinstance(proof, dict):
        return _invalid("bundle.proof is missing or not an object")
    event = bundle.get("event")
    if not isinstance(event, dict):
        event = {}
    canonical = event.get("canonical")
    if canonical is not None and not isinstance(canonical, dict):
        return _invalid("bundle.event.canonical is present but not an object")
    leaf = proof.get("leaf")

    # DEWP §6.5: a compliant verifier MUST reject any kind other than the ones it implements.
    kind = bundle.get("kind")
    if kind is not None and kind != BUNDLE_KIND:
        return _invalid(f'refusing bundle kind "{kind}" (expected "{BUNDLE_KIND}") — DEWP §6.5')

    # DEWP §4.5: an unknown Application Profile means the leaf layout is one this port cannot
    # reproduce. Leaf binding is then NOT ATTEMPTED (None), never silently "failed" — and the bundle
    # cannot be ok, because vouching for a layout we do not implement is the thing to avoid.
    profile = bundle.get("profile")
    unknown_profile = profile is not None and profile != AUDIT_PROFILE
    if unknown_profile:
        notes.append(
            f'bundle declares profile "{profile}"; this verifier implements only "{AUDIT_PROFILE}", '
            "so leaf binding was not attempted"
        )

    anchor = bundle.get("anchor")
    anchor = anchor if isinstance(anchor, dict) else {}
    if trusted_root is not None:
        daily_root = trusted_root
        root_source = "independent"
    elif anchor.get("dailyRoot"):
        daily_root = anchor["dailyRoot"]
        root_source = "self-asserted"
    else:
        daily_root = None
        root_source = "none"

    try:
        inclusion_ok = daily_root is not None and verify_inclusion_proof(proof, daily_root)
    except Exception:
        inclusion_ok = False
    root_consistency = daily_root is not None and proof.get("checkpointRoot") == daily_root
    commitment_verified = bool(inclusion_ok and root_consistency)

    # None = not attempted (unknown profile / no preimage), True = bound, False = mismatch.
    leaf_binding: Optional[bool]
    if unknown_profile or canonical is None:
        leaf_binding = None
    else:
        try:
            leaf_binding = leaf_hash(canonical) == leaf
        except Exception:
            leaf_binding = False

    # The bundle duplicates seq/createdAt/type/outcome/detail/signerDid/signature/sigAlg alongside
    # `canonical`, and ONLY `canonical` is hashed into the leaf. Unchecked, a bundle could display
    # outcome "SUCCESS" over a committed "FAILURE" and still return FULLY_VERIFIED — the commitment
    # genuine, the caption over it free-form. The auditor reads the caption.
    header_binding: Optional[bool]
    if canonical is None:
        header_binding = None
    else:
        mismatch = None
        for label, shown, committed in (
            ("seq", event.get("seq"), canonical.get("seq")),
            ("proof.seq", proof.get("seq"), canonical.get("seq")),
            ("createdAt", event.get("createdAt"), canonical.get("createdAt")),
            ("type", event.get("type"), canonical.get("event")),
            ("outcome", event.get("outcome"), canonical.get("outcome")),
            ("detail", event.get("detail"), canonical.get("detail")),
            ("signerDid", event.get("signerDid"), canonical.get("signerDid")),
            ("signature", event.get("signature"), canonical.get("signature")),
            ("sigAlg", event.get("sigAlg"), canonical.get("sigAlg")),
        ):
            if shown is not None and str(shown) != str(committed):
                mismatch = f'displayed {label} ("{shown}") does not match the committed value ("{committed}")'
                break
        header_binding = mismatch is None
        if mismatch:
            notes.append(f"{mismatch} — the bundle displays something other than what was committed")

    content_verified = bool(commitment_verified and leaf_binding is True and header_binding is not False)

    # signatureVerified would re-verify the embedded DIV ES256 signature; kept out of this port to
    # avoid pulling a crypto dependency into the ledger module (the TS verifier does it). Reporting
    # False caps a signed event below FULLY_VERIFIED, which is the honest direction.
    signature_verified = False

    # DEWP §3.7: anchorVerified holds if and only if the root is verified against an anchor QUORUM —
    # at least `requiredAnchors` distinct trusted issuers signing the SAME dailyRoot. This port
    # implements no anchor signature check, no quorum and no divergence detection, so it cannot
    # satisfy that under any argument. It previously set anchorVerified purely because a root was
    # passed in, which asserted more than was checked. An unverified anchor is not a verified one.
    anchor_verified = False
    if commitment_verified and root_source == "independent":
        notes.append(
            "an independently supplied root was used, but this port does not verify anchor "
            "signatures or quorum (DEWP §5.2/§5.3), so anchorVerified stays false and "
            "FULLY_VERIFIED is not reachable here — use @intyga/verify for anchor quorum"
        )

    properties = {
        "commitmentVerified": commitment_verified,
        "contentVerified": content_verified,
        "signatureVerified": signature_verified,
        "anchorVerified": anchor_verified,
    }
    has_signer = bool(
        isinstance(canonical, dict)
        and canonical.get("signature")
        and canonical.get("signerPublicKey")
    )
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
        "ok": bool(
            commitment_verified
            and content_verified
            and root_source == "independent"
            and not unknown_profile
        ),
        "rootSource": root_source,
        "properties": properties,
        "checks": {"leafBinding": leaf_binding, "headerBinding": header_binding},
        "verificationLevel": level,
        "notes": notes,
    }


def _invalid(reason: str) -> Dict[str, Any]:
    """A refusal shaped like every other verdict, so a caller never has to catch to stay safe."""
    return {
        "ok": False,
        "rootSource": "none",
        "properties": {
            "commitmentVerified": False,
            "contentVerified": False,
            "signatureVerified": False,
            "anchorVerified": False,
        },
        "checks": {"leafBinding": None, "headerBinding": None},
        "verificationLevel": "INVALID",
        "notes": [reason],
    }
