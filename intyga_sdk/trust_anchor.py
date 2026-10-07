"""The customer-authored trust-anchor file — port of ``packages/sdk/src/trust-anchor.ts``.

This file IS the relying party's pinning (DIV §4.4.6, identity-associating anchor): it names the
approver identities that may sign and, for each stable DID, the public keys that speak for it. It is
exported from the console (or written by hand) and carried in the relying party's own configuration,
so — unlike the gateway-SIGNED trust bundle (:mod:`intyga_sdk.trust_bundle`) — it carries no
signature: adopting the file into your configuration is itself the act of trust.

Self-certifying entries (``did:intyga:key:…``) may list no keys in an ONLINE anchor: the DID commits to
the enrolled key, and the verifier checks the receipt-carried key against that commitment.
"""

import json
import re
from typing import Any, Dict, List, Optional, Sequence

from ._jsutil import b64_length, is_integer, json_loads, strict_equal

TRUST_ANCHOR_FILE_TYPE = "intyga-trust-anchor"
SELF_CERTIFYING_DID_PREFIX = "did:intyga:key:"

_BASE64 = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")
_HTTP_ORIGIN = re.compile(r"https?://")


class InvalidTrustAnchorFile(ValueError):
    """A trust-anchor file that must not be trusted. The message names exactly one problem."""


def _fail(detail: str) -> InvalidTrustAnchorFile:
    return InvalidTrustAnchorFile(f"invalid trust-anchor file: {detail}")


def _is_base64(s: str) -> bool:
    return _BASE64.fullmatch(s) is not None and b64_length(s) > 0


_ABSENT = object()


def _js(value: Any) -> str:
    """``JSON.stringify(value)`` for an error message (``undefined`` for a missing value)."""
    if value is _ABSENT:
        return "undefined"
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return repr(value)


def parse_trust_anchor_file(json_text: Any, *, purpose: Optional[str] = "online") -> Dict[str, Any]:
    """Parse and validate a trust-anchor file. Raises :class:`InvalidTrustAnchorFile` (a ``ValueError``)
    with a precise, single-problem reason — a trust anchor is security configuration, so a malformed
    one fails loudly at load time rather than surfacing later as an unverifiable receipt.

    ``purpose`` is what the CALLER is about to verify — ``"online"`` (the default: passkeys and node
    keys, ordinary approval receipts) or ``"offline"`` (offline signing keys, DIV §5a offline
    approvals) — and the file must say the same. A file with no ``purpose`` predates the field and is
    an online anchor. The returned dict is the file with ``purpose`` always set.
    """
    expected = purpose if purpose is not None else "online"
    try:
        raw = json_loads(json_text)
    except Exception as exc:  # noqa: BLE001 - any parse failure is the same refusal
        raise _fail(f"not valid JSON ({exc})") from None
    if not isinstance(raw, dict):
        raise _fail("root must be an object")
    obj = raw

    if obj.get("type") != TRUST_ANCHOR_FILE_TYPE:
        raise _fail(
            f'type must be "{TRUST_ANCHOR_FILE_TYPE}" — a div-trust-bundle JWS (offline approval) is a '
            "different, gateway-signed artifact and cannot be used here"
        )
    if not strict_equal(obj.get("v"), 1):
        raise _fail(f"unsupported version {_js(obj.get('v', _ABSENT))} (expected 1)")
    file_purpose = obj.get("purpose", "online")
    if file_purpose != "online" and file_purpose != "offline":
        raise _fail(f'purpose must be "online" or "offline", got {_js(obj.get("purpose"))}')
    if file_purpose != expected:
        raise _fail(
            f"this is an {file_purpose} anchor, but it is being loaded to verify {expected} approvals — "
            f"export the {expected} anchor instead"
        )
    epoch = obj.get("epoch")
    if not is_integer(epoch) or epoch < 0:
        raise _fail("epoch must be a non-negative integer")
    if "label" in obj and not isinstance(obj["label"], str):
        raise _fail("label must be a string")
    if "exportedAt" in obj and not isinstance(obj["exportedAt"], str):
        raise _fail("exportedAt must be a string")

    approvers = obj.get("approvers")
    if not isinstance(approvers, list) or not approvers:
        raise _fail("approvers must be a non-empty array — an empty anchor would trust nobody")
    seen = set()
    for entry in approvers:
        if not isinstance(entry, dict):
            raise _fail("every approvers[] entry must be an object")
        did = entry.get("did", _ABSENT)
        keys = entry.get("publicKeys", _ABSENT)
        if not isinstance(did, str) or not did.startswith("did:"):
            raise _fail(f'approver did {_js(did)} must be a string starting with "did:"')
        if did in seen:
            raise _fail(f"duplicate approver did {did}")
        seen.add(did)
        if not isinstance(keys, list):
            raise _fail(f"approver {did}: publicKeys must be an array")
        for key in keys:
            if not isinstance(key, str) or not _is_base64(key):
                raise _fail(f"approver {did}: every publicKeys[] entry must be a base64 SPKI or COSE key")
        # A stable DID with no keys can never satisfy verification — refuse at load, where the problem
        # is diagnosable. Self-certifying DIDs are the exception for an ONLINE anchor only: a DID
        # commits to its online key, not to an offline signing key its owner chose to register.
        if not keys and file_purpose == "offline":
            raise _fail(f"approver {did} has no publicKeys — an offline anchor must pin every offline key")
        if not keys and not did.startswith(SELF_CERTIFYING_DID_PREFIX):
            raise _fail(
                f"approver {did} has no publicKeys and is not self-certifying "
                f"({SELF_CERTIFYING_DID_PREFIX}…) — a receipt from them could never verify"
            )

    if "webauthn" in obj:
        w = obj["webauthn"]
        if not isinstance(w, dict):
            raise _fail("webauthn must be an object")
        if not isinstance(w.get("origin"), str) or not _HTTP_ORIGIN.match(w["origin"]):
            raise _fail("webauthn.origin must be an http(s) origin string")
        if not isinstance(w.get("rpId"), str) or not w["rpId"]:
            raise _fail("webauthn.rpId must be a non-empty string")

    return {**obj, "purpose": file_purpose}


def trust_anchor_approvers(
    anchor_file: Dict[str, Any], limit_to_dids: Optional[Sequence[str]] = None
) -> Dict[str, Any]:
    """The verifier's DID-mode trust anchor from a parsed file: ``{"dids": [...], "resolveKey": ...}``,
    one identity per approver however many keys it holds. ``resolveKey`` returns None for a DID with no
    pinned keys (a self-certifying entry) or not in the file. ``limit_to_dids`` narrows, never widens.
    """
    by_did: Dict[str, List[str]] = {}
    for a in anchor_file.get("approvers") or []:
        if limit_to_dids is not None and a.get("did") not in limit_to_dids:
            continue
        by_did[a["did"]] = list(a.get("publicKeys") or [])

    def resolve_key(did: str) -> Optional[List[str]]:
        keys = by_did.get(did)
        return list(keys) if keys else None

    return {"dids": list(by_did), "resolveKey": resolve_key}
