"""Offline approval (docs/DIV.md §5a) — the relying-party half. Port of ``packages/sdk/src/offline.ts``;
the contract is docs/OFFLINE-APPROVAL-SDK.md and the conformance suite
``packages/mcp-schemas/vectors/offline-approval-vectors.json``.

When the gateway is unreachable, the relying party builds the challenge ITSELF, the humans review and
sign it on a disconnected device, and the result is verified by the ordinary §5 procedure. The signing
ceremony moves off the network; it does not move earlier in time — pre-signing approvals would put a
bearer capability on disk and capture a judgment about a hypothetical (DIV §5a.1).

Four properties are enforced structurally rather than by convention:

1. IT ONLY APPLIES WHEN WE COULD NOT ASK. The client falls back exclusively on a transport failure or
   a 5xx — never on a 4xx, DENIED or EXPIRED, where a human or the policy said no.
2. IT RETURNS A DISTINCT STATUS. A completed fallback reports ``OFFLINE_APPROVED``, never ``APPROVED``,
   so adding offline capability to an existing ``if status != "APPROVED": raise`` guard permits nothing.
3. THE POLICY COMES FROM THE BUNDLE, NOT FROM HERE. The requirement is read from the signed trust
   bundle (§5a.4); there is no parameter for it and no local default to fall back on.
4. NOTHING PERSISTS THAT AUTHORIZES ANYTHING. What is written to disk records that an approval
   HAPPENED (for reconciliation). No file written here can authorize a future action.

Data crossing a process or language boundary — challenges, witnesses, receipts, pending records — is
a dict in its camelCase wire shape, exactly as the verifier functions in :mod:`intyga_sdk.crypto` take
and return them. Results that can be refused are ``{"ok": False, "reason": ...}``, never an exception.
"""

import base64
import inspect
import json
import os
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Union,
)

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from ._jsutil import (
    b64url_decode_strict,
    epoch_ms,
    iso_from_ms,
    is_number,
    is_safe_integer,
    js_trim,
    json_dumps,
    json_loads,
    now_utc,
    timestamp_ms,
    to_iso_string,
)
from ._secure_files import create_private_marker, ensure_private_dir, write_private_file
from .crypto import (
    DIV_OFFLINE_INTENT_TYPE,
    MAX_OFFLINE_WINDOW_MINUTES,
    NonCanonicalValue,
    base64url_encode,
    canonical_offline_intent_payload,
    requires_hardware_credential,
    verification_code,
    verify_approval_receipt,
    verify_delegation,
)
from .trust_bundle import (
    approver_anchor,
    check_trust_bundle_freshness,
    load_trust_bundle,
    requirement_for,
)

#: Wire prefix for a challenge travelling OUT to the approvers.
CHALLENGE_ENVELOPE_PREFIX = "DIV1:"
#: Wire prefix for a signature coming BACK from an approver.
SIGNATURE_ENVELOPE_PREFIX = "SIG1:"

#: Default validity window. Deliberately short: an offline approval is created and redeemed inside one
#: incident, and the window is the only bound on a proof that no one can revoke.
DEFAULT_OFFLINE_WINDOW_MINUTES = 15

_SAFE_NONCE = re.compile(r"[A-Za-z0-9._-]{1,200}")

PathLike = Union[str, "os.PathLike[str]"]
Warn = Callable[[str], None]


def _refuse(reason: Optional[str]) -> Dict[str, Any]:
    return {"ok": False, "reason": reason}


def _is_path_safe_nonce(nonce: Any) -> bool:
    """Nonces become path segments in the redemption store and the reconciliation buffer, so anything
    that could traverse out of those directories is refused rather than trusted."""
    return isinstance(nonce, str) and _SAFE_NONCE.fullmatch(nonce) is not None


def _default_warn(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


# ── challenge ───────────────────────────────────────────────────────────────────────────────────────


def create_offline_challenge(
    *,
    bundle: Mapping[str, Any],
    target: str,
    action_type: str,
    display: str,
    params: Dict[str, Any],
    requester: Dict[str, Any],
    window_minutes: Optional[float] = None,
    as_of: Optional[datetime] = None,
    nonce: Optional[str] = None,
    delegation: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build an offline challenge for an action, taking the approval requirement from the trust bundle.

    Returns ``{"ok": True, "challenge": {...}}`` or ``{"ok": False, "reason": ...}``. The challenge dict
    carries ``nonce``, ``canonicalPayload`` (the exact bytes approvers sign), ``verificationCode`` (read
    back to the operator before signing, DIV §5a.8), ``envelope`` (``DIV1:…``, what travels to the
    approvers), ``challengedAt``, ``expiresAt``, ``target``, ``actionType``, ``display``, ``params``,
    ``requester``, ``requirement`` and ``approverDids``.

    The requirement is NOT a parameter: a relying party that supplied its own would be choosing the
    quorum its own action must clear (DIV §5a.3). Refused: a blank target (DIV Target Isolation); an
    action the bundle has no unambiguous rule for (there is no implicit 1-of-1); a hardware-key or authenticator-allowlist rule (it cannot be met
    offline); a nonce that is not a safe path segment (a supplied empty nonce is refused, never
    replaced); a window that is not a whole number of minutes; a ``delegation`` whose
    ``delegatedQuorum`` is below the rule's quorum (it narrows WHO approves, never HOW MANY, §5a.5).

    ``window_minutes`` must be a whole number; it is clamped to 1..60 (default 15). ``as_of`` overrides "now" and ``nonce`` the
    generated ``off_<uuid4>``, for conformance vectors and replay; production callers omit both. A
    ``delegation`` is one already verified by :func:`intyga_sdk.verify_delegation`: under it the signed
    quorum becomes ``delegatedQuorum`` and the eligible set ``delegatedTo``.
    """
    # DIV §3 Invariant 5 (Target Isolation): a blank target binds no execution environment, so the
    # approval would verify at every relying party that also asserts it.
    if not isinstance(target, str) or not js_trim(target):
        return _refuse("target is required (DIV Target Isolation)")
    resolved = requirement_for(bundle, action_type, display)
    if resolved is None:
        return _refuse(
            f'the trust bundle has no approval rule matching "{action_type}" that can be selected '
            "unambiguously — configure the rule or export a fresh bundle with rule-selection metadata "
            "(DIV §5a.3)"
        )
    # Refused at CHALLENGE time as well as at verification: sending approvers a payload nobody can
    # produce a valid signature for wastes the one resource an incident is short of.
    if requires_hardware_credential(resolved["requirement"]):
        return _refuse(
            f'"{action_type}" requires a hardware-backed WebAuthn credential, which cannot be produced '
            "offline — this action cannot be approved out of band (DIV §5a.3)"
        )

    if window_minutes is not None and not is_safe_integer(window_minutes):
        return _refuse("windowMinutes must be a whole number of minutes")
    window = min(
        MAX_OFFLINE_WINDOW_MINUTES,
        max(1, int(window_minutes if window_minutes is not None else DEFAULT_OFFLINE_WINDOW_MINUTES)),
    )
    now = epoch_ms(as_of if as_of is not None else now_utc())
    challenged_at = iso_from_ms(now)
    expires_at = iso_from_ms(now + window * 60_000)
    if nonce is None:
        nonce = f"off_{uuid.uuid4()}"
    if not _is_path_safe_nonce(nonce):
        return _refuse("nonce must be a safe path segment")

    # "Narrows who may approve, never the policy" has to be enforced, not merely intended (DIV §5a.5).
    # display may differ between sealing and use, and display is not what selects the rule here, so
    # without this a delegation sealed under a permissive rule could overwrite a strict quorum.
    rule_quorum = resolved["requirement"]["requiredApprovals"]
    if delegation is not None:
        delegated_quorum = delegation.get("delegatedQuorum")
        if not is_number(delegated_quorum):
            return _refuse("the delegation carries no delegatedQuorum")
        if delegated_quorum < rule_quorum:
            return _refuse(
                f'this delegation would lower the quorum for "{action_type}" from {rule_quorum} to '
                f"{delegated_quorum}. A delegation may narrow WHO approves, never HOW MANY (DIV §5a.5)"
            )
        # Under a delegation the eligible set and the quorum are the DELEGATED ones. Everything else in
        # the requirement still comes from the bundle.
        requirement = {**resolved["requirement"], "requiredApprovals": delegated_quorum}
        approver_dids = list(delegation.get("delegatedTo") or [])
    else:
        requirement = resolved["requirement"]
        approver_dids = resolved["approverDids"]

    if not isinstance(requester, dict):
        return _refuse('requester must be {"did": ..., "attestation": ...}')
    try:
        canonical = canonical_offline_intent_payload(
            target=target,
            action_type=action_type,
            display=display,
            params=params,
            requester=requester,
            requirement=requirement,
            nonce=nonce,
            challenged_at=challenged_at,
            expires_at=expires_at,
        )
    except (NonCanonicalValue, RecursionError) as exc:
        return _refuse(f"the action cannot be canonicalized: {exc}")

    return {
        "ok": True,
        "challenge": {
            "nonce": nonce,
            "canonicalPayload": canonical,
            "verificationCode": verification_code(canonical),
            "envelope": CHALLENGE_ENVELOPE_PREFIX + base64url_encode(canonical.encode("utf-8")),
            "challengedAt": challenged_at,
            "expiresAt": expires_at,
            "target": target,
            "actionType": action_type,
            "display": display,
            "params": params,
            "requester": requester,
            "requirement": requirement,
            "approverDids": approver_dids,
        },
    }


def decode_challenge_envelope(envelope: str) -> Dict[str, Any]:
    """Decode a ``DIV1:`` envelope for review by an approver's signing tool.

    Returns ``{"ok": True, "challenge": {...}}`` — ``canonicalPayload``, ``verificationCode``,
    ``target``, ``actionType``, ``display``, ``params``, ``requester``, ``requirement``, ``nonce``,
    ``challengedAt``, ``expiresAt`` — or a refusal.

    Only a canonical, well-shaped ``div-offline-intent`` decodes: ``target``, ``actionType``,
    ``display``, ``nonce``, ``challengedAt`` and ``expiresAt`` strings with a non-blank target, ``params``
    and ``requirement`` objects, and a ``requester`` object with a string ``did``. Surrounding
    whitespace is trimmed as JavaScript's ``String.prototype.trim`` does. The type check matters even here: a signing tool
    must not sign an ORDINARY intent someone pasted in, because that signature would be a live
    approval produced outside the gateway's single-use accounting. And the parsed fields must
    re-canonicalize to the exact bytes: otherwise the review pane would show something other than what
    is signed, and the signature would verify nowhere.
    """
    if not isinstance(envelope, str):
        return _refuse(f"not a challenge envelope (expected a {CHALLENGE_ENVELOPE_PREFIX} prefix)")
    trimmed = js_trim(envelope)
    if not trimmed.startswith(CHALLENGE_ENVELOPE_PREFIX):
        return _refuse(f"not a challenge envelope (expected a {CHALLENGE_ENVELOPE_PREFIX} prefix)")
    try:
        canonical = b64url_decode_strict(trimmed[len(CHALLENGE_ENVELOPE_PREFIX):]).decode("utf-8", "replace")
    except Exception:
        return _refuse("challenge envelope is not valid base64url")
    try:
        parsed = json_loads(canonical)
    except Exception:
        return _refuse("challenge envelope does not contain a JSON payload (truncated paste?)")
    if not isinstance(parsed, dict):
        return _refuse("challenge payload is not a JSON object")
    if parsed.get("type") != DIV_OFFLINE_INTENT_TYPE:
        if "type" in parsed:
            shown = "null" if parsed["type"] is None else str(parsed["type"])
        else:
            shown = "undefined"
        return _refuse(
            f"this is a {shown} payload, not an offline approval challenge — refusing to sign it"
        )
    # Shapes before bytes. Canonicalization alone would accept `"target": 5` whenever it re-serializes
    # identically, and the approver would then review — and sign — something no relying party builds.
    shape_problem = _challenge_shape_problem(parsed)
    if shape_problem:
        return _refuse(f"challenge payload {shape_problem} — refusing to sign it")
    display = parsed["display"]
    try:
        rebuilt = canonical_offline_intent_payload(
            target=parsed.get("target"),
            action_type=parsed.get("actionType"),
            display=display,
            params=parsed.get("params"),
            requester=parsed.get("requester"),
            requirement=parsed.get("requirement"),
            nonce=parsed.get("nonce"),
            challenged_at=parsed.get("challengedAt"),
            expires_at=parsed.get("expiresAt"),
        )
    except Exception:  # noqa: BLE001 - a missing or mistyped field is the same refusal
        return _refuse("challenge payload carries values that cannot be canonicalized — refusing to sign it")
    if rebuilt != canonical:
        return _refuse(
            "challenge payload is not canonical — re-serializing it produces different bytes, so a "
            "signature over it would verify nowhere"
        )
    return {
        "ok": True,
        "challenge": {
            "canonicalPayload": canonical,
            "verificationCode": verification_code(canonical),
            "target": parsed.get("target"),
            "actionType": parsed.get("actionType"),
            "display": display,
            "params": parsed.get("params"),
            "requester": parsed.get("requester"),
            "requirement": parsed.get("requirement"),
            "nonce": parsed.get("nonce"),
            "challengedAt": parsed.get("challengedAt"),
            "expiresAt": parsed.get("expiresAt"),
        },
    }


def _challenge_shape_problem(p: Dict[str, Any]) -> Optional[str]:
    """Why a decoded challenge payload has the wrong shape, or None when every field is well-typed.
    The same shapes every SDK refuses (docs/OFFLINE-APPROVAL-SDK.md, "Envelopes"). ``json.loads``
    yields exactly ``str`` for a JSON string and ``dict`` for an object, so these checks cannot be
    satisfied by a number, a bool, a list or null."""
    for field in ("target", "actionType", "display", "nonce", "challengedAt", "expiresAt"):
        if not isinstance(p.get(field), str):
            return f"field {field} is not a string"
    if not js_trim(p["target"]):
        return "has a blank target"
    if not isinstance(p.get("params"), dict):
        return "params is not a JSON object"
    requester = p.get("requester")
    if not isinstance(requester, dict) or not isinstance(requester.get("did"), str):
        return "requester is not an identity"
    if not isinstance(p.get("requirement"), dict):
        return "requirement is not a JSON object"
    return None


# ── signatures ──────────────────────────────────────────────────────────────────────────────────────


def encode_signature_envelope(witness: Mapping[str, Any]) -> str:
    """Encode one approver's signature for the trip back: ``SIG1:`` + base64url of
    ``{"did":…,"key":…,"sig":…,"alg":…}`` — exactly that key order, no whitespace, so the text is
    byte-identical to every other SDK's. ``witness`` is ``{"signerDid", "signerPublicKey", "signature",
    "sigAlg"}``; a missing ``sigAlg`` is ``ES256``."""
    compact: Dict[str, Any] = {}
    # JSON.stringify drops an undefined member; a present None is null. Mirror both.
    for out_key, in_key in (("did", "signerDid"), ("key", "signerPublicKey"), ("sig", "signature")):
        if in_key in witness:
            compact[out_key] = witness[in_key]
    alg = witness.get("sigAlg")
    compact["alg"] = "ES256" if alg is None else alg
    return SIGNATURE_ENVELOPE_PREFIX + base64url_encode(json_dumps(compact).encode("utf-8"))


def decode_signature_envelope(envelope: str) -> Dict[str, Any]:
    """Decode a ``SIG1:`` envelope into ``{"ok": True, "witness": {...}}`` or a refusal. Strict
    base64url of a JSON object; ``did``, ``key`` and ``sig`` must be non-empty strings, and ``alg``,
    when present, a non-empty string (a missing one is ``ES256``)."""
    if not isinstance(envelope, str):
        return _refuse(f"not a signature envelope (expected a {SIGNATURE_ENVELOPE_PREFIX} prefix)")
    trimmed = js_trim(envelope)
    if not trimmed.startswith(SIGNATURE_ENVELOPE_PREFIX):
        return _refuse(f"not a signature envelope (expected a {SIGNATURE_ENVELOPE_PREFIX} prefix)")
    try:
        compact = json_loads(
            b64url_decode_strict(trimmed[len(SIGNATURE_ENVELOPE_PREFIX):]).decode("utf-8", "replace")
        )
    except Exception:
        return _refuse("signature envelope is not valid base64url JSON (truncated paste?)")
    # A pasted null or array must be a refusal of that envelope, never an exception that ends the
    # whole ceremony over one bad paste.
    if not isinstance(compact, dict):
        return _refuse("signature envelope is not a JSON object")
    if not all(isinstance(compact.get(k), str) and compact.get(k) for k in ("did", "key", "sig")):
        return _refuse("signature envelope is missing did, key or sig")
    alg = compact.get("alg")
    if "alg" in compact and not (isinstance(alg, str) and alg):
        return _refuse("signature envelope alg must be a string")
    return {
        "ok": True,
        "witness": {
            "signerDid": compact["did"],
            "signerPublicKey": compact["key"],
            "signature": compact["sig"],
            "sigAlg": "ES256" if alg is None else alg,
        },
    }


PrivateKeyInput = Union[ec.EllipticCurvePrivateKey, str, bytes]


def _load_private_key(private_key: Any) -> Any:
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key
    if isinstance(private_key, str):
        return serialization.load_pem_private_key(private_key.encode("utf-8"), password=None)
    if isinstance(private_key, (bytes, bytearray, memoryview)):
        data = bytes(private_key)
        if b"-----BEGIN" in data:
            return serialization.load_pem_private_key(data, password=None)
        return serialization.load_der_private_key(data, password=None)
    raise TypeError(f"unsupported key type {type(private_key).__name__}")


def sign_challenge_envelope(
    envelope: str,
    *,
    private_key: PrivateKeyInput,
    signer_did: str,
    as_of: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Sign a ``DIV1:`` challenge as an approver — the library half of ``intyga sign``.

    Returns ``{"ok": True, "envelope": "SIG1:…", "challenge": {...decoded...}}`` or a refusal.

    Decodes first (so only a canonical ``div-offline-intent`` is ever signed) and refuses a challenge
    whose ``expiresAt`` is unreadable or already past, a ``signer_did`` that is not a DID, and any key
    that is not a P-256 private key. ``private_key`` is the approver's offline signing key: an
    ``EllipticCurvePrivateKey``, a PEM string/bytes, or DER PKCS#8 bytes. The signature is ES256 over
    the canonical payload's UTF-8 bytes in IEEE P1363 (r‖s) form, and the envelope's ``key`` is the
    signer's base64 SPKI. A PEM may be PKCS#8 (``PRIVATE KEY``) or SEC1 (``EC PRIVATE KEY``, what
    ``openssl ecparam -genkey`` writes).

    It shows nothing. The caller MUST have shown the decoded challenge to the approver and had them
    confirm the verification code with the operator first (DIV §5a.8) — an approver who signs an
    opaque blob has approved nothing.
    """
    decoded = decode_challenge_envelope(envelope)
    if not decoded["ok"]:
        return _refuse(decoded["reason"])
    challenge = decoded["challenge"]
    # A timestamp we cannot read is not one we can say is still valid (DIV §6.2).
    expiry = timestamp_ms(challenge["expiresAt"])
    if expiry is None:
        return _refuse("expiresAt is not a valid RFC3339 timestamp — refusing to sign")
    if expiry <= epoch_ms(as_of if as_of is not None else now_utc()):
        return _refuse("this challenge has already expired — ask for a fresh one")
    if not isinstance(signer_did, str) or not signer_did.startswith("did:"):
        return _refuse("signerDid must be a DID")

    try:
        key = _load_private_key(private_key)
    except Exception as exc:  # noqa: BLE001 - every unreadable key is the same refusal
        return _refuse(f"could not read the private key: {exc}")
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        return _refuse("the signing key must be a P-256 (prime256v1) private key")

    der = key.sign(challenge["canonicalPayload"].encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    signature = _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {
        "ok": True,
        "challenge": challenge,
        "envelope": encode_signature_envelope(
            {
                "signerDid": signer_did,
                "signerPublicKey": _b64(spki),
                "signature": signature,
                "sigAlg": "ES256",
            }
        ),
    }


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def assemble_offline_receipt(challenge: Mapping[str, Any], witnesses: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Assemble the collected witnesses into a receipt the ordinary verifier can check."""
    return {
        "canonicalPayload": challenge["canonicalPayload"],
        "target": challenge["target"],
        "actionType": challenge["actionType"],
        "actionDescription": challenge["display"],
        "params": challenge["params"],
        "signatures": [dict(w) for w in witnesses],
        "requester": challenge["requester"],
        "verificationCode": challenge["verificationCode"],
    }


# ── single use ──────────────────────────────────────────────────────────────────────────────────────


class RedemptionStore(Protocol):
    """Records which offline nonces this relying party has already redeemed.

    Single use is inherently stateful and LOCAL (DIV §5 steps 9-10). Because the relying party
    generates its own nonce, single use within it is fully enforceable — unlike a pre-signed token,
    which two relying parties could each redeem unaware.
    """

    def redeem(self, nonce: str) -> bool:
        """Claim ``nonce``. MUST be atomic and MUST return False if it was already claimed."""
        ...


class FileRedemptionStore:
    """Default store: one ``<nonce>.used`` file per redeemed nonce, created with ``O_CREAT|O_EXCL``.

    The exclusive create is atomic on POSIX and Windows — the OS refuses the open if the path exists,
    so two processes racing the same nonce cannot both succeed. A read-then-write check would lose
    that race, which is the whole point of the store. The file holds the redemption time.
    """

    def __init__(self, directory: PathLike):
        self._dir = os.fspath(directory)
        ensure_private_dir(self._dir)

    def redeem(self, nonce: str) -> bool:
        if not _is_path_safe_nonce(nonce):
            return False
        try:
            return create_private_marker(
                os.path.join(self._dir, f"{nonce}.used"), to_iso_string(now_utc())
            )
        except Exception:  # noqa: BLE001 - any failure to claim is "not claimed"
            return False


# ── running an offline approval ─────────────────────────────────────────────────────────────────────

CollectSignatures = Callable[[Dict[str, Any]], Union[Iterable[str], Awaitable[Iterable[str]]]]


@dataclass
class OfflineApprovalOptions:
    """Options for :func:`use_offline_approval` and the client's ``require_approval(offline=...)``.

    ``bundle_dir`` holds the signed trust bundle and pinned gateway key (:func:`save_trust_bundle`).
    ``requester_did`` is this workload's own identity, bound into the signed bytes.
    ``collect_signatures(challenge)`` gets the challenge to the approvers and returns their raw ``SIG1:``
    strings (sync or async). It is a seam, not a default: moving the envelope is a human, site-specific
    act — a terminal prompt, a QR code, a phone call — and inventing one here would assume connectivity.

    Optional: ``delegation_dir`` (``*.json`` delegation receipts, for when the approvers are unreachable
    too); ``store`` (default :class:`FileRedemptionStore` at ``<bundle_dir>/.redeemed``); ``buffer_dir``
    (pending records, default ``<bundle_dir>/.pending``); ``window_minutes`` (1..60, default 15);
    ``warn`` (default: stderr — this must never be quiet); ``as_of`` (overrides "now").
    """

    bundle_dir: PathLike
    requester_did: str
    collect_signatures: CollectSignatures
    delegation_dir: Optional[PathLike] = None
    store: Optional[RedemptionStore] = None
    buffer_dir: Optional[PathLike] = None
    window_minutes: Optional[float] = None
    warn: Optional[Warn] = None
    as_of: Optional[datetime] = None


def _coerce_options(options: Any) -> OfflineApprovalOptions:
    if isinstance(options, OfflineApprovalOptions):
        return options
    if isinstance(options, Mapping):
        return OfflineApprovalOptions(**options)
    raise TypeError("options must be OfflineApprovalOptions or a mapping of its fields")


def _requirement_floor(rule: Mapping[str, Any]) -> Dict[str, Any]:
    """The DIV §5 step 3d floor a bundle rule imposes on a signed requirement."""
    return {
        "requiredApprovals": rule["requiredApprovals"],
        "requesterCannotApprove": rule["requesterCannotApprove"],
        "requireHardwareKey": rule["requireHardwareKey"],
    }


def _expected_problem(expected: Any) -> Optional[str]:
    if not isinstance(expected, Mapping):
        return 'expected must be {"target", "actionType", "display", "params"}'
    for key in ("target", "actionType", "display"):
        if not isinstance(expected.get(key), str):
            return f"expected['{key}'] must be a string"
    if not js_trim(expected["target"]):
        return "expected['target'] is required (DIV Target Isolation)"
    if not isinstance(expected.get("params"), dict):
        return "expected['params'] must be a dict (pass {} when there are none)"
    return None


async def use_offline_approval(
    expected: Mapping[str, Any], options: Union[OfflineApprovalOptions, Mapping[str, Any]]
) -> Dict[str, Any]:
    """Run a full offline approval: build the challenge, collect signatures out of band, verify, redeem.

    ``expected`` is ``{"target", "actionType", "display", "params"}`` — what this relying party is about
    to execute. Returns ``{"ok": True, "receipt", "nonce", "signers", "viaDelegation"}`` or a refusal.

    1. Load and verify the trust bundle.
    2. With ``delegation_dir``, use the first ``*.json`` delegation that verifies against the bundle's
       ORDINARY approvers and is at least as strict as the rule; report every other file via ``warn``.
    3. Build the challenge and call ``collect_signatures``.
    4. Recheck bundle freshness; decode the envelopes, discarding unreadable ones.
    5. Verify with :func:`intyga_sdk.verify_approval_receipt` (``allow_offline=True``) against the
       eligible approvers' offline-intent anchor and the ordinary rule's floor, so target isolation,
       exact params, quorum, four-eyes, expiry and the window cap all apply unchanged.
    If ``collect_signatures`` raises, that exception propagates: nothing is buffered or redeemed.

    6. Buffer the pending record, THEN redeem the nonce — a crash between the two leaves a record to
       reconcile rather than an executed approval nobody hears about. A nonce that cannot be redeemed
       clears its record and is refused.
    7. Warn loudly that an offline approval was used.

    Async because ``collect_signatures`` may be; from synchronous code use ``asyncio.run(...)``.
    """
    opts = _coerce_options(options)
    warn = opts.warn or _default_warn
    bundle_dir = os.fspath(opts.bundle_dir)

    problem = _expected_problem(expected)
    if problem:
        return _refuse(problem)

    loaded = load_trust_bundle(bundle_dir, as_of=opts.as_of)
    if not loaded["ok"]:
        return _refuse(loaded.get("reason"))
    bundle = loaded["bundle"]

    # TIER 3: consulted only when a delegation is actually on disk, and verified against the bundle's
    # ORDINARY approver set — those entitled to approve are the ones who must have delegated.
    delegation = None
    if opts.delegation_dir is not None:
        found = _find_delegation(os.fspath(opts.delegation_dir), bundle, expected, opts.as_of)
        if found.get("reason"):
            warn(f"⚠ OFFLINE APPROVAL: {found['reason']}")
        delegation = found.get("delegation")

    built = create_offline_challenge(
        bundle=bundle,
        target=expected["target"],
        action_type=expected["actionType"],
        display=expected["display"],
        params=expected["params"],
        requester={"did": opts.requester_did, "attestation": None},
        window_minutes=opts.window_minutes,
        as_of=opts.as_of,
        delegation=delegation,
    )
    if not built["ok"]:
        return _refuse(built["reason"])
    challenge = built["challenge"]

    raw = opts.collect_signatures(challenge)
    if inspect.isawaitable(raw):
        raw = await raw
    freshness = check_trust_bundle_freshness(bundle, as_of=opts.as_of)
    if not freshness["ok"]:
        return freshness
    if isinstance(raw, str):
        raw = [raw]
    raw = list(raw or [])
    if not raw:
        return _refuse("no signatures were collected — the action is not approved")

    witnesses: List[Dict[str, Any]] = []
    rejected: List[str] = []
    for envelope in raw:
        decoded = decode_signature_envelope(envelope)
        if not decoded["ok"]:
            rejected.append(decoded.get("reason") or "unreadable signature envelope")
            continue
        witnesses.append(decoded["witness"])
    if not witnesses:
        return _refuse(f"no usable signatures ({'; '.join(rejected)})")

    receipt = assemble_offline_receipt(challenge, witnesses)
    # DIV §5 step 3d. The signed requirement is the signers' own statement, so it is held to the
    # bundle's ORDINARY rule, re-resolved here rather than read back from the challenge. Under a
    # delegation that is still the right floor: create_offline_challenge refused a lower quorum.
    ordinary = requirement_for(bundle, expected["actionType"], expected["display"])
    if ordinary is None:
        return _refuse("no unambiguous approval rule applies to this action")
    result = verify_approval_receipt(
        receipt,
        {
            "target": expected["target"],
            "actionType": expected["actionType"],
            "params": expected["params"],
            "nonce": challenge["nonce"],
            # Only the approvers eligible for THIS action, so a valid signature from outside the rule's
            # list does not count. The one place offline signing keys count: this is a div-offline-intent.
            "approvers": approver_anchor(bundle, challenge["approverDids"], "offline-intent"),
            "requirement": _requirement_floor(ordinary["requirement"]),
        },
        allow_offline=True,
        delegation=delegation,
        as_of=opts.as_of,
    )
    if not result.get("ok"):
        detail = f" (also discarded: {'; '.join(rejected)})" if rejected else ""
        return _refuse(f"{result.get('reason')}{detail}")

    try:
        store = opts.store if opts.store is not None else FileRedemptionStore(os.path.join(bundle_dir, ".redeemed"))
    except Exception as exc:  # noqa: BLE001 - surfaced as a refusal, before anything is buffered
        return _refuse(f"could not open the redemption store: {exc}")
    # Buffer BEFORE redeeming: a crash between the two must leave a pending record behind. A spurious
    # record reconciles harmlessly; the opposite order could leave a redeemed, executed approval
    # invisible to reconciliation forever.
    _buffer_for_reconciliation(challenge, receipt, delegation, opts, bundle_dir, warn)
    if not store.redeem(challenge["nonce"]):
        clear_pending_approval(challenge["nonce"], bundle_dir, opts.buffer_dir)
        return _refuse(f"nonce {challenge['nonce']} has already been redeemed here")

    signers = result.get("signers")
    via = delegation.get("nonce") if delegation is not None else None
    warn(
        f'⚠ OFFLINE APPROVAL USED — "{expected["display"]}" ({expected["actionType"]} on '
        f'{expected["target"]}). Approved out of band by '
        f'{", ".join(signers) if signers is not None else "(unknown)"} because Intyga was unreachable'
        f'{f", under delegation {via}" if delegation is not None else ""}. '
        f"Nonce {challenge['nonce']} is buffered for reconciliation; report it when connectivity returns."
    )
    return {
        "ok": True,
        "receipt": receipt,
        "nonce": challenge["nonce"],
        "signers": signers,
        "viaDelegation": via,
    }


def _find_delegation(
    directory: str,
    bundle: Mapping[str, Any],
    expected: Mapping[str, Any],
    as_of: Optional[datetime],
) -> Dict[str, Any]:
    """Find and verify a delegation covering this exact action. A file that fails to verify is
    REPORTED, not silently skipped: a delegation the operator believes they hold but which does not
    apply is exactly what they need to be told during an incident."""
    resolved = requirement_for(bundle, expected["actionType"], expected["display"])
    if resolved is None:
        return {
            "reason": "no unambiguous ordinary approval rule applies to this delegation — export a fresh "
            "trust bundle"
        }
    try:
        names = sorted(n for n in os.listdir(directory) if n.endswith(".json"))
    except OSError:
        return {}
    ordinary = resolved["requirement"]
    rejected: List[str] = []
    for name in names:
        try:
            with open(os.path.join(directory, name), "r", encoding="utf-8") as f:
                receipt = json_loads(f.read())
        except Exception:  # noqa: BLE001
            rejected.append(f"{name}: unreadable")
            continue
        res = verify_delegation(
            receipt,
            {
                # The ORDINARY approver set — whoever may approve this action is who must have
                # delegated it. Ordinary keys only: an offline signing key must never seal a delegation.
                "approvers": approver_anchor(bundle, resolved["approverDids"], "ordinary"),
                "target": expected["target"],
                "actionType": expected["actionType"],
                "params": expected["params"],
                # DIV §5 step 3d / §5a.5: the sealing requirement may not be weaker than the rule. The
                # AAGUID comparison below stays, because the floor does not cover allowedAaguids.
                "requirement": _requirement_floor(ordinary),
            },
            as_of=as_of,
        )
        if not res.get("ok") or not res.get("delegation"):
            rejected.append(f"{name}: {res.get('reason')}")
            continue
        # The verification above binds this requirement to the seal's signatures. Incident quorum alone
        # is insufficient: a 3-of-N delegation must not be sealed by a 1-of-N ceremony, nor drop an
        # ordinary four-eyes/hardware restriction (DIV §5a.5).
        sealed = json.loads(receipt["canonicalPayload"])["requirement"]
        sealed_aaguids = sealed.get("allowedAaguids") or []
        weaker_aaguids = bool(ordinary["allowedAaguids"]) and (
            not sealed_aaguids or any(a not in ordinary["allowedAaguids"] for a in sealed_aaguids)
        )
        if (
            sealed["requiredApprovals"] < ordinary["requiredApprovals"]
            or (ordinary["requireHardwareKey"] and sealed.get("requireHardwareKey") is not True)
            or (ordinary["requesterCannotApprove"] and sealed.get("requesterCannotApprove") is not True)
            or weaker_aaguids
        ):
            rejected.append(f"{name}: delegation sealing requirement is weaker than the ordinary approval rule")
            continue
        return {"delegation": res["delegation"]}
    return {"reason": f"no delegation applies ({'; '.join(rejected)})"} if rejected else {}


# ── pending records ─────────────────────────────────────────────────────────────────────────────────


def _buffer_dir(bundle_dir: Optional[PathLike], buffer_dir: Optional[PathLike]) -> str:
    if buffer_dir is not None:
        return os.fspath(buffer_dir)
    if bundle_dir is None:
        raise ValueError("bundle_dir or buffer_dir is required")
    return os.path.join(os.fspath(bundle_dir), ".pending")


def _buffer_for_reconciliation(
    challenge: Mapping[str, Any],
    receipt: Dict[str, Any],
    delegation: Optional[Mapping[str, Any]],
    opts: OfflineApprovalOptions,
    bundle_dir: str,
    warn: Warn,
) -> None:
    """Record the approval so it can be reported when the gateway is reachable again.

    Best effort by design: a buffering failure must never block the emergency action the operator is
    mid-incident on. It is warned about loudly instead, because an unrecorded approval is exactly the
    case reconciliation exists to surface.
    """
    nonce = challenge["nonce"]
    record: Dict[str, Any] = {
        "nonce": nonce,
        "target": challenge["target"],
        "actionType": challenge["actionType"],
        "display": challenge["display"],
        "usedAt": to_iso_string(now_utc()),
        "receipt": receipt,
    }
    if delegation is not None and delegation.get("nonce") is not None:
        record["delegationNonce"] = delegation["nonce"]
    try:
        if not _is_path_safe_nonce(nonce):
            raise ValueError("nonce is not a safe path segment")
        directory = _buffer_dir(bundle_dir, opts.buffer_dir)
        ensure_private_dir(directory)
        write_private_file(os.path.join(directory, f"{nonce}.json"), json_dumps(record, indent=2) + "\n")
    except Exception as exc:  # noqa: BLE001 - best effort, but never silent
        warn(
            f"⚠ OFFLINE APPROVAL: could not buffer {nonce} for reconciliation ({exc}). Report this "
            "manually — an unreported approval is indistinguishable from an unauthorized one."
        )


def read_pending_approvals(
    bundle_dir: Optional[PathLike], buffer_dir: Optional[PathLike] = None
) -> Dict[str, List[Any]]:
    """The buffered records, and the names of the files that could not be read.

    Returns ``{"records": [...], "unreadable": [file names]}``, both in file-name order, from
    ``<bundle_dir>/.pending/`` (or ``buffer_dir``). Each record is read on its own: one unreadable file
    must not hide the others, and a record nobody can read is still an approval nobody has reported —
    :meth:`IntygaClient.reconcile_offline_approvals` counts it as failed and names it. A file is
    unreadable when it is not JSON, or not an object with a string ``nonce``.
    """
    directory = _buffer_dir(bundle_dir, buffer_dir)
    try:
        names = sorted(n for n in os.listdir(directory) if n.endswith(".json"))
    except OSError:
        return {"records": [], "unreadable": []}
    records: List[Dict[str, Any]] = []
    unreadable: List[str] = []
    for name in names:
        try:
            with open(os.path.join(directory, name), "r", encoding="utf-8") as f:
                record = json_loads(f.read())
        except Exception:  # noqa: BLE001 - every unreadable file is reported the same way
            record = None
        if isinstance(record, dict) and isinstance(record.get("nonce"), str):
            records.append(record)
        else:
            unreadable.append(name)
    return {"records": records, "unreadable": unreadable}


def pending_approvals(
    bundle_dir: Optional[PathLike], buffer_dir: Optional[PathLike] = None
) -> List[Dict[str, Any]]:
    """The offline approvals buffered by :func:`use_offline_approval` and not yet reported.

    Each is ``{"nonce", "target", "actionType", "display", "usedAt", "receipt", "delegationNonce"?}``
    (``delegationNonce`` is omitted, never null, when no delegation was used). Unreadable files are
    left out here; :func:`read_pending_approvals` names them.
    """
    return read_pending_approvals(bundle_dir, buffer_dir)["records"]


def clear_pending_approval(
    nonce: str, bundle_dir: Optional[PathLike], buffer_dir: Optional[PathLike] = None
) -> None:
    """Clear a buffered approval once the gateway has acknowledged it.

    Only call this on a definite acknowledgement: dropping the record on a network error would turn a
    retryable report into a permanently unreported approval. A nonce that is not a safe path segment
    (it may have been echoed back by the gateway) is ignored rather than allowed to name another path.
    """
    if not _is_path_safe_nonce(nonce):
        return
    try:
        os.unlink(os.path.join(_buffer_dir(bundle_dir, buffer_dir), f"{nonce}.json"))
    except OSError:
        pass  # already gone
