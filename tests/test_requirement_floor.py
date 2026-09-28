"""DIV §5 step 3d (H1): the relying party's own requirement floor.

The signed ``requirement`` is authored by the signers, so one approver who is also the requester can
self-compose a 1-of-1 receipt for a 3-of-3 four-eyes action. Without a floor it verifies (legacy
behaviour, pinned here); with the relying party's floor it is refused on every entry point that
counts a quorum.
"""

import base64
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from intyga_sdk import WEAKER_REQUIREMENT_REASON  # noqa: E402
from intyga_sdk.crypto import (  # noqa: E402
    canonical_agent_authority_payload,
    canonical_delegation_payload,
    canonical_intent_payload,
    verify_agent_authority,
    verify_approval_receipt,
    verify_delegation,
)

WEAK = {
    "requiredApprovals": 1,
    "requireHardwareKey": False,
    "allowedAaguids": [],
    "requesterCannotApprove": False,
    "signerClass": "human",
}
REQUESTER = {"did": "did:ex:alice", "attestation": None}
PARAMS = {"amount": 1000000, "to": "acct-9"}


def _pair():
    key = ec.generate_private_key(ec.SECP256R1())
    spki = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    return key, spki


PEOPLE = {did: _pair() for did in ("did:ex:alice", "did:ex:bob", "did:ex:carol")}
APPROVERS = {"dids": list(PEOPLE), "resolveKey": lambda did: PEOPLE[did][1] if did in PEOPLE else None}


def _receipt(canonical, display, params, signers):
    return {
        "canonicalPayload": canonical,
        "actionDescription": display,
        "params": params,
        "requester": REQUESTER,
        "signatures": [{
            "signerDid": did,
            "signerPublicKey": PEOPLE[did][1],
            "sigAlg": "ES256",
            "signature": base64.b64encode(
                PEOPLE[did][0].sign(canonical.encode("utf-8"), ec.ECDSA(hashes.SHA256()))).decode(),
        } for did in signers],
    }


class TestRequirementFloor(unittest.TestCase):
    def setUp(self):
        canonical = canonical_intent_payload(
            "prod-payments", "payments.wire", "Wire", PARAMS, REQUESTER, WEAK,
            "c_real_nonce", "2999-01-01T00:00:00.000Z")
        self.forged = _receipt(canonical, "Wire", PARAMS, ["did:ex:alice"])
        self.expected = {"target": "prod-payments", "nonce": "c_real_nonce", "actionType": "payments.wire",
                         "params": PARAMS, "approvers": APPROVERS}

    def test_without_floor_only_the_signers_own_quorum_is_proved(self):
        self.assertEqual(verify_approval_receipt(self.forged, self.expected),
                         {"ok": True, "signers": ["did:ex:alice"]})

    def test_floor_refuses_self_composed_downgrade(self):
        result = verify_approval_receipt(self.forged, {
            **self.expected, "requirement": {"requiredApprovals": 3, "requesterCannotApprove": True}})
        self.assertFalse(result["ok"])
        self.assertIn(WEAKER_REQUIREMENT_REASON, result["reason"])

    def test_each_weaker_field_and_malformed_floor_refused(self):
        for floor in ({"requiredApprovals": 1, "requesterCannotApprove": True},
                      {"requiredApprovals": 1, "requireHardwareKey": True},
                      {"requiredApprovals": 0}, {"requiredApprovals": True}, {"requiredApprovals": "3"}, {}):
            result = verify_approval_receipt(self.forged, {**self.expected, "requirement": floor})
            self.assertFalse(result["ok"], floor)

    def test_equal_floor_passes(self):
        result = verify_approval_receipt(self.forged, {**self.expected, "requirement": {"requiredApprovals": 1}})
        self.assertTrue(result["ok"], result.get("reason"))

    def test_delegation_and_authority_seals_are_floored(self):
        now = datetime.now(timezone.utc)
        sealed = now.isoformat().replace("+00:00", "Z")
        expires = (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        seal = _receipt(canonical_delegation_payload(
            "prod", "restart", "Restart", {}, REQUESTER, WEAK, ["did:ex:bob"], 1, "d_nonce", sealed, expires),
            "Restart", {}, ["did:ex:alice"])
        dx = {"target": "prod", "actionType": "restart", "params": {}, "approvers": APPROVERS}
        self.assertTrue(verify_delegation(seal, dx)["ok"])
        result = verify_delegation(seal, {**dx, "requirement": {"requiredApprovals": 2}})
        self.assertFalse(result["ok"])
        self.assertIn(WEAKER_REQUIREMENT_REASON, result["reason"])

        authority = _receipt(canonical_agent_authority_payload(
            "prod", ["restart"], "Restart", {"did": "did:ex:agent"}, REQUESTER, WEAK, "a_nonce", sealed, expires),
            "Restart", {}, ["did:ex:alice"])
        ax = {"target": "prod", "agentDid": "did:ex:agent", "approvers": APPROVERS}
        self.assertTrue(verify_agent_authority(authority, ax)["ok"])
        result = verify_agent_authority(authority, {**ax, "requirement": {"requiredApprovals": 2}})
        self.assertFalse(result["ok"])
        self.assertIn(WEAKER_REQUIREMENT_REASON, result["reason"])


if __name__ == "__main__":
    unittest.main()
