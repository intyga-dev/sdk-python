"""Offline trust bundle (docs/DIV.md §5a.4) — the relying party's local answer to "whose signature
counts, and what does policy require?". Port of ``packages/sdk/src/trust-bundle.ts``.

Offline verification needs two things the network normally supplies: the approver public keys (DIV
Invariant 3 forbids taking them from the proof under verification) and the approval REQUIREMENT. The
relying party builds its own offline challenge, so if it also invented the quorum it would be setting
its own policy. The bundle is the offline projection of the tenant's real policy, exported while the
gateway was reachable, as a compact JWS (RS256) verified against the gateway key PINNED at export.

A bundle is a dict in its wire shape (``v``, ``type``, ``approvers``, ``policy``, ...); see
docs/OFFLINE-APPROVAL-SDK.md for the on-disk layout every SDK shares.
"""

import os
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ._jsutil import (
    b64url_decode_strict,
    epoch_ms,
    is_integer,
    is_safe_integer,
    js_trim,
    json_dumps,
    json_loads,
    now_utc,
    strict_equal,
    timestamp_ms,
)
from ._secure_files import ensure_private_dir, write_private_file
from .approval_policy import ApprovalPolicyConflict, select_approval_rule, validate_exact_approval_policy

#: Bundle ``type`` discriminator, inside the signed JWS payload.
DIV_TRUST_BUNDLE_TYPE = "div-trust-bundle-v1"

#: Hard ceiling on bundle age, enforced regardless of the ``expiresAt`` the gateway wrote. A stale
#: bundle is a stale approver set: a revoked approver stays trusted, a tightened quorum stays loose.
MAX_TRUST_BUNDLE_AGE_DAYS = 30

#: File names inside a bundle directory. Shared by every SDK, so one directory serves them all.
TRUST_BUNDLE_FILE = "trust-bundle.jws"
GATEWAY_KEY_FILE = "gateway-key.jwk.json"

_DAY_MS = 86_400_000

PathLike = Union[str, "os.PathLike[str]"]


def _refuse(reason: str) -> Dict[str, Any]:
    return {"ok": False, "reason": reason}


def _rsa_public_key(jwk: Any) -> rsa.RSAPublicKey:
    """The pinned gateway key. RSA only: RS256 means an RSA key, and a pinned EC key must not get
    ECDSA verification under an RS256 header — the key choice deciding the algorithm."""
    if not isinstance(jwk, Mapping):
        raise ValueError("the JWK is not an object")
    if jwk.get("kty") != "RSA":
        raise ValueError(f"expected an RSA key (kty RSA), got {jwk.get('kty')!r}")
    n, e = jwk.get("n"), jwk.get("e")
    if not isinstance(n, str) or not isinstance(e, str) or not n or not e:
        raise ValueError("the RSA JWK is missing n or e")
    return rsa.RSAPublicNumbers(
        int.from_bytes(b64url_decode_strict(e), "big"), int.from_bytes(b64url_decode_strict(n), "big")
    ).public_key()


def _non_empty_strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) and v for v in value)


def _valid_bundle_approver(a: Any) -> bool:
    if not isinstance(a, dict):
        return False
    did, keys = a.get("did"), a.get("publicKeys")
    if not isinstance(did, str) or not did or not isinstance(keys, list) or not keys:
        return False
    if not _non_empty_strings(keys):
        return False
    # Optional, but when present it must be a list: null is not "absent".
    return "offlinePublicKeys" not in a or _non_empty_strings(a["offlinePublicKeys"])


_MISSING = object()


def _valid_bundle_policy(p: Any) -> bool:
    """A complete v1 policy entry — every constraint present, so none can be defaulted away."""
    if not isinstance(p, dict) or p.get("signerClass") != "human":
        return False
    pattern = p.get("actionPattern")
    if not isinstance(pattern, str) or not js_trim(pattern):
        return False
    if not is_safe_integer(p.get("requiredApprovals")) or p["requiredApprovals"] < 1:
        return False
    for field in ("requireHardwareKey", "requesterCannotApprove", "requireAttestedRequester"):
        if not isinstance(p.get(field), bool):
            return False
    for field in ("approverDids", "allowedAaguids", "allowedIssuers", "escalationApproverDids"):
        if not _non_empty_strings(p.get(field)):
            return False
    escalate = p.get("escalateAfterSeconds", _MISSING)
    if escalate is not None and (not is_safe_integer(escalate) or escalate < 1):
        return False
    for field in ("autoApproveRequesterDid", "autoApproveWindowStart", "autoApproveWindowEnd"):
        value = p.get(field, _MISSING)
        if value is not None and not isinstance(value, str):
            return False
    day = p.get("autoApproveDayOfWeek", _MISSING)
    return day is None or (is_integer(day) and 0 <= day <= 6)


def _is_version_one(value: Any) -> bool:
    return strict_equal(value, 1)


def verify_trust_bundle(
    jws: str, gateway_jwk: Mapping[str, Any], *, as_of: Optional[datetime] = None
) -> Dict[str, Any]:
    """Verify a compact JWS bundle against a PINNED gateway key and return its payload.

    Returns ``{"ok": True, "bundle": {...}}`` or ``{"ok": False, "reason": ...}``.

    Only RS256 is accepted, and the header's ``alg`` is checked against that fixed expectation rather
    than used to select an algorithm: trusting it is the classic JWS confusion bug (``none`` skips
    verification, an HMAC alg would verify a MAC keyed with the public key). Freshness is checked
    last; ``as_of`` overrides "now" for tests and replay.
    """
    if not isinstance(jws, str):
        return _refuse("trust bundle is not a compact JWS")
    parts = jws.split(".")
    if len(parts) != 3:
        return _refuse("trust bundle is not a compact JWS")
    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json_loads(b64url_decode_strict(header_b64).decode("utf-8", "replace"))
    except Exception:
        return _refuse("trust bundle header is not JSON")
    if not isinstance(header, dict):
        return _refuse("invalid trust bundle header")
    alg = header.get("alg")
    if alg != "RS256":
        return _refuse(f"trust bundle alg must be RS256, got {'(none)' if alg is None else alg}")

    # RS256 means an RSA key: never let the pinned key's type choose the algorithm either.
    if not isinstance(gateway_jwk, Mapping) or gateway_jwk.get("kty") != "RSA":
        return _refuse("pinned gateway key must be an RSA JWK")
    try:
        key = _rsa_public_key(gateway_jwk)
    except Exception as exc:
        return _refuse(f"pinned gateway key is unusable: {exc}")

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8", "surrogatepass")
    try:
        key.verify(b64url_decode_strict(sig_b64), signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return _refuse("trust bundle signature does not verify against the pinned gateway key")
    except Exception as exc:
        return _refuse(f"trust bundle signature check failed: {type(exc).__name__}")

    try:
        bundle = json_loads(b64url_decode_strict(payload_b64).decode("utf-8", "replace"))
    except Exception:
        return _refuse("trust bundle payload is not JSON")
    if not isinstance(bundle, dict):
        return _refuse("invalid trust bundle payload")
    if bundle.get("type") != DIV_TRUST_BUNDLE_TYPE or not _is_version_one(bundle.get("v")):
        return _refuse("unsupported trust bundle type or version")
    unmatched = bundle.get("unmatchedActionPolicy")
    if unmatched not in ("DENY", "BASELINE"):
        return _refuse("trust bundle has no valid unmatched-action decision")
    approvers = bundle.get("approvers")
    if not isinstance(approvers, list) or not approvers:
        return _refuse("trust bundle names no approvers")
    if not all(_valid_bundle_approver(a) for a in approvers):
        return _refuse("invalid bundle approver keys")
    # A key listed as both ordinary and offline-only would undo the split the second list exists for.
    ordinary_keys = {k for a in approvers for k in a["publicKeys"]}
    if any(k in ordinary_keys for a in approvers for k in a.get("offlinePublicKeys", [])):
        return _refuse("trust bundle lists an offline signing key as an ordinary key")
    policy = bundle.get("policy")
    if not isinstance(policy, list) or not all(_valid_bundle_policy(p) for p in policy):
        return _refuse("trust bundle carries invalid or incomplete policy")
    try:
        validate_exact_approval_policy(policy)
    except ApprovalPolicyConflict as conflict:
        return _refuse(f"trust bundle has invalid exact-action policy: {', '.join(conflict.fields)}")
    if unmatched == "BASELINE" and not any(r["actionPattern"] == "*" for r in policy):
        return _refuse("trust bundle has no baseline for unknown actions")

    freshness = check_trust_bundle_freshness(bundle, as_of=as_of)
    if not freshness["ok"]:
        return freshness
    return {"ok": True, "bundle": bundle}


def check_trust_bundle_freshness(
    bundle: Mapping[str, Any], *, as_of: Optional[datetime] = None
) -> Dict[str, Any]:
    """Recheck a verified bundle — e.g. after an out-of-band signing ceremony — without its keys.

    Two independent staleness checks: now must not be after ``expiresAt``, and the bundle must be at
    most :data:`MAX_TRUST_BUNDLE_AGE_DAYS` old (exactly 30 days is accepted). The gateway's own
    expiry can be set generously; the local age cap is what actually bounds drift.
    """
    if not isinstance(bundle, Mapping):
        return _refuse("invalid trust bundle payload")
    now = epoch_ms(as_of if as_of is not None else now_utc())
    expiry = timestamp_ms(bundle.get("expiresAt"))
    if expiry is None:
        return _refuse("trust bundle expiresAt is not a valid RFC3339 timestamp")
    if now > expiry:
        return _refuse(f"trust bundle expired at {bundle.get('expiresAt')} — export a fresh one")
    issued = timestamp_ms(bundle.get("issuedAt"))
    if issued is None:
        return _refuse("trust bundle issuedAt is not a valid RFC3339 timestamp")
    age_ms = now - issued
    if age_ms > MAX_TRUST_BUNDLE_AGE_DAYS * _DAY_MS:
        return _refuse(
            f"trust bundle is {age_ms / _DAY_MS:.1f} days old, over the {MAX_TRUST_BUNDLE_AGE_DAYS}-day "
            "maximum — export a fresh one"
        )
    return {"ok": True}


def save_trust_bundle(directory: PathLike, jws: str, gateway_jwk: Mapping[str, Any]) -> None:
    """Write a bundle and its pinned verification key into ``directory`` for use during a later outage.

    Writes ``trust-bundle.jws`` and ``gateway-key.jwk.json`` (directory ``0700``, files ``0600``), the
    layout every SDK reads.
    """
    d = os.fspath(directory)
    ensure_private_dir(d)
    write_private_file(os.path.join(d, TRUST_BUNDLE_FILE), jws)
    write_private_file(os.path.join(d, GATEWAY_KEY_FILE), json_dumps(dict(gateway_jwk), indent=2) + "\n")


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def load_trust_bundle(directory: PathLike, *, as_of: Optional[datetime] = None) -> Dict[str, Any]:
    """Load and verify the bundle saved in ``directory``.

    Fails closed and LOUDLY: there is deliberately no "continue without a bundle" path, because the
    fallback would be an unverified approver set — the one thing DIV Invariant 3 forbids.
    """
    d = os.fspath(directory)
    bundle_path = os.path.join(d, TRUST_BUNDLE_FILE)
    key_path = os.path.join(d, GATEWAY_KEY_FILE)
    try:
        jws = js_trim(_read_text(bundle_path))
    except Exception:
        return _refuse(
            f"no trust bundle at {bundle_path} — export one with `intyga trust-bundle export` while "
            "the gateway is reachable"
        )
    try:
        jwk = json_loads(_read_text(key_path))
    except Exception:
        return _refuse(f"no pinned gateway key at {key_path}")
    return verify_trust_bundle(jws, jwk, as_of=as_of)


def approver_anchor(
    bundle: Mapping[str, Any],
    limit_to_dids: Optional[Sequence[str]] = None,
    purpose: str = "ordinary",
) -> Dict[str, Any]:
    """A DID-mode trust anchor from the bundle: ``{"dids": [...], "resolveKey": did -> [keys] | None}``,
    the shape ``verify_approval_receipt`` and ``verify_delegation`` take as ``expected["approvers"]``.

    DID mode is load-bearing: quorum counts distinct APPROVERS, and every key of one approver resolves
    to that one identity. ``limit_to_dids`` narrows the eligible set (an empty list narrows it to
    nobody); it never widens it.

    ``purpose`` is ``"ordinary"`` (the default: ``publicKeys`` only — what a delegation or an ordinary
    intent is verified against) or ``"offline-intent"`` (adds ``offlinePublicKeys``; ONLY for verifying a
    ``div-offline-intent``). A bare offline key that could seal a delegation would hand its holder the
    approval authority the delegation transfers (DIV §5a.4). Any other value raises ``ValueError``.
    """
    if purpose not in ("ordinary", "offline-intent"):
        raise ValueError(f'purpose must be "ordinary" or "offline-intent", got {purpose!r}')
    by_did: Dict[str, List[str]] = {}
    for a in bundle.get("approvers") or []:
        if limit_to_dids is not None and a.get("did") not in limit_to_dids:
            continue
        keys = list(a.get("publicKeys") or [])
        if purpose == "offline-intent":
            keys += list(a.get("offlinePublicKeys") or [])
        by_did[a.get("did")] = keys

    def resolve_key(did: str) -> Optional[List[str]]:
        keys = by_did.get(did)
        return list(keys) if keys is not None else None

    return {"dids": list(by_did), "resolveKey": resolve_key}


def requirement_for(
    bundle: Mapping[str, Any], action_type: Optional[str], display: str = ""
) -> Optional[Dict[str, Any]]:
    """Resolve the approval requirement for an action from the bundle's offline policy projection.

    Returns ``{"requirement": {...}, "approverDids": [...]}`` or None (refusal). Selection is the
    gateway's exact-ID algorithm (:func:`intyga_sdk.approval_policy.select_approval_rule`): validate
    the whole policy, refuse a differently cased match, take the exact rule, else ``*`` only under
    ``BASELINE``. ``display`` is accepted for parity with the other SDKs and never selects a rule.

    None when the action is unmatched, the policy conflicts or is malformed, the rule has fewer
    distinct approvers than its quorum, or it uses a control an offline ceremony cannot reproduce
    (``requireAttestedRequester``, ``allowedIssuers``, escalation, an auto-approve requester).
    """
    if (
        not isinstance(bundle, Mapping)
        or not _is_version_one(bundle.get("v"))
        or bundle.get("type") != DIV_TRUST_BUNDLE_TYPE
        or bundle.get("unmatchedActionPolicy") not in ("DENY", "BASELINE")
        or not isinstance(bundle.get("policy"), list)
        or not all(_valid_bundle_policy(p) for p in bundle["policy"])
    ):
        return None
    try:
        winner = select_approval_rule(bundle["policy"], action_type, bundle["unmatchedActionPolicy"])
    except ApprovalPolicyConflict:
        return None
    # These online-only conditions cannot be reconstructed by an offline ceremony.
    if (
        winner is None
        or len(set(winner["approverDids"])) < winner["requiredApprovals"]
        or winner["requireAttestedRequester"]
        or winner["allowedIssuers"]
        or winner["escalateAfterSeconds"]
        or winner["autoApproveRequesterDid"]
    ):
        return None
    return {
        "requirement": {
            "requiredApprovals": max(1, int(winner["requiredApprovals"])),
            "requireHardwareKey": winner["requireHardwareKey"],
            "allowedAaguids": list(winner["allowedAaguids"]),
            "requesterCannotApprove": winner["requesterCannotApprove"],
            "signerClass": "human",
        },
        "approverDids": list(winner["approverDids"]),
    }

