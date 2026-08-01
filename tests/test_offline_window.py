"""Regression tests for the offline validity-window cap (DIV §5a.3).

The window check used to be written ``if expiry_probe is not None: <checks>``, so an ``expiresAt``
this port could not parse skipped the cap AND the negative-window sanity check. The only other place
``expiresAt`` is parsed is the expiry check, and that one is disabled by ``allow_expired`` — so
``allow_offline + allow_expired``, the documented forensic re-verification mode and the only mode
under which an offline proof is examined at all, left the window completely unbounded.

``expiresAt`` is inside the signed bytes, but an offline proof is minted by whoever constructs it and
the verifier reconstructs the payload from the receipt's OWN ``expiresAt``, so any string
round-trips. DIV §5a.3 makes the window the entire revocation story for an offline proof — a relying
party verifying out of band has no channel to recall one — so an unbounded window turned a
60-minute incident credential into a permanent bearer capability for that action.

The trigger here is the ES5 extended-year form, which ``Date.parse`` in the TS reference accepts and
``datetime.fromisoformat`` does not. The same defect was live in the Go and Rust ports, each with a
different trigger; the fix landed in TS first and in one port only.
"""

import base64
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from intyga_sdk.crypto import (  # noqa: E402
    MAX_OFFLINE_WINDOW_MINUTES,
    canonical_offline_intent_payload,
    verify_approval_receipt,
)

REQUESTER = {"did": "did:intyga:service:pipeline", "attestation": None}
REQUIREMENT = {
    "requiredApprovals": 1,
    "requireHardwareKey": False,
    "allowedAaguids": [],
    "requesterCannotApprove": False,
}
PARAMS = {"environment": "prod"}
NONCE = "off-window-test"


def signed_offline_receipt(challenged_at: str, expires_at: str):
    key = ec.generate_private_key(ec.SECP256R1())
    pub = base64.b64encode(
        key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode()

    canonical = canonical_offline_intent_payload(
        "prod-db", "deleteDatabase", "Drop prod", PARAMS,
        REQUESTER, REQUIREMENT, NONCE, challenged_at, expires_at,
    )
    der = key.sign(canonical.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")  # IEEE P1363

    receipt = {
        "canonicalPayload": canonical,
        "actionDescription": "Drop prod",
        "params": PARAMS,
        "signatures": [{
            "signerDid": "did:intyga:human:alice",
            "signerPublicKey": pub,
            "signature": base64.b64encode(raw).decode(),
            "sigAlg": "ES256",
        }],
        "requester": REQUESTER,
        "verificationCode": "",
    }
    expected = {
        "target": "prod-db",
        "actionType": "deleteDatabase",
        "params": PARAMS,
        "nonce": NONCE,
        "approvers": {"publicKeys": [pub]},
    }
    return receipt, expected


class TestOfflineWindow(unittest.TestCase):
    def test_unparseable_expires_at_is_refused_not_skipped(self):
        # ~10-year windows against a 60-minute cap. Each previously returned ok=True.
        # Note `2036-01-01T00:00:00` is absent: this port's parser accepts a zone-less timestamp as
        # UTC, so it is refused by the window cap rather than by the parse. That is a mild parity
        # difference with Go, which rejects it — the outcome is a refusal either way, which is what
        # matters here. The overlong-window case below covers that path.
        for expires_at in [
            "+002036-01-01T00:00:00.000Z",  # ES5 extended year — the trigger for this port
            "9999-99-99T99:99:99Z",
            "garbage",
        ]:
            with self.subTest(expiresAt=expires_at):
                receipt, expected = signed_offline_receipt("2026-01-01T00:00:00Z", expires_at)
                r = verify_approval_receipt(
                    receipt, expected, allow_offline=True, allow_expired=True
                )
                self.assertFalse(
                    r["ok"],
                    f"accepted a ~10-year window against a {MAX_OFFLINE_WINDOW_MINUTES}-minute cap",
                )
                self.assertIn("expiresAt is not a valid RFC3339 timestamp", r["reason"])

    def test_overlong_but_parseable_window_is_refused(self):
        receipt, expected = signed_offline_receipt(
            "2026-01-01T00:00:00Z", "2036-01-01T00:00:00Z"
        )
        r = verify_approval_receipt(receipt, expected, allow_offline=True, allow_expired=True)
        self.assertFalse(r["ok"])
        self.assertIn("over the", r["reason"])

    def test_a_proof_inside_the_cap_still_verifies(self):
        # The fix must not turn every offline proof into a refusal.
        now = datetime.now(timezone.utc)
        receipt, expected = signed_offline_receipt(
            (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            (now + timedelta(minutes=25)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        r = verify_approval_receipt(receipt, expected, allow_offline=True, allow_expired=True)
        self.assertTrue(r["ok"], f"refused a well-formed 30-minute offline proof: {r.get('reason')}")


if __name__ == "__main__":
    unittest.main()
