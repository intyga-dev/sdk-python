import json
import unittest
from datetime import datetime, timezone

from intyga_sdk.crypto import (
    DIV_TENANT_BOUND_VERSION,
    canonical_agent_authority_payload,
    canonical_delegation_payload,
    canonical_intent_payload,
    canonical_offline_intent_payload,
    canonical_platform_intent_payload,
    verify_approval_receipt,
)
from intyga_sdk.trust_anchor import InvalidTrustAnchorFile, parse_trust_anchor_file


REQUESTER = {"did": "did:intyga:service:test", "attestation": None}
REQUIREMENT = {
    "requiredApprovals": 1,
    "requireHardwareKey": False,
    "allowedAaguids": [],
    "requesterCannotApprove": False,
    "signerClass": "human",
}
PARAMS = {"amount": "10"}
TENANT = "Tenant-A"


class TestTenantBoundCanonicalPayloads(unittest.TestCase):
    def test_all_five_payload_kinds_emit_v2_with_exact_tenant(self):
        builders = {
            "ordinary": lambda: canonical_intent_payload(
                "target", "action", "Display", PARAMS, REQUESTER, REQUIREMENT,
                "nonce", "2027-01-01T00:00:00.000Z", tenant_id=TENANT,
            ),
            "offline": lambda: canonical_offline_intent_payload(
                "target", "action", "Display", PARAMS, REQUESTER, REQUIREMENT, "nonce",
                "2026-10-10T00:00:00.000Z", "2026-10-10T00:15:00.000Z", tenant_id=TENANT,
            ),
            "delegation": lambda: canonical_delegation_payload(
                "target", "action", "Display", PARAMS, REQUESTER, REQUIREMENT,
                ["did:intyga:alice"], 1, "nonce", "2026-10-10T00:00:00.000Z",
                "2026-10-11T00:00:00.000Z", tenant_id=TENANT,
            ),
            "authority": lambda: canonical_agent_authority_payload(
                "target", ["action"], "Display", {"did": "did:intyga:agent"}, REQUESTER,
                REQUIREMENT, "nonce", "2026-10-10T00:00:00.000Z",
                "2026-10-11T00:00:00.000Z", tenant_id=TENANT,
            ),
            "platform": lambda: canonical_platform_intent_payload(
                "a" * 64, "example.com", "subject", "2026-10-10T00:00:00.000Z",
                "2026-10-10T00:05:00.000Z", "nonce", tenant_id=TENANT,
            ),
        }
        for name, build in builders.items():
            with self.subTest(name=name):
                payload = json.loads(build())
                self.assertEqual(payload["v"], DIV_TENANT_BOUND_VERSION)
                self.assertEqual(payload["tenantId"], TENANT)

    def test_absent_tenant_preserves_v1_and_explicit_empty_is_refused(self):
        legacy = json.loads(canonical_intent_payload(
            "target", "action", "Display", PARAMS, REQUESTER, REQUIREMENT,
            "nonce", "2027-01-01T00:00:00.000Z",
        ))
        self.assertEqual(legacy["v"], 1)
        self.assertNotIn("tenantId", legacy)
        with self.assertRaisesRegex(ValueError, "non-empty"):
            canonical_intent_payload(
                "target", "action", "Display", PARAMS, REQUESTER, REQUIREMENT,
                "nonce", "2027-01-01T00:00:00.000Z", tenant_id="",
            )
        with self.assertRaisesRegex(ValueError, "non-empty"):
            canonical_intent_payload(
                "target", "action", "Display", PARAMS, REQUESTER, REQUIREMENT,
                "nonce", "2027-01-01T00:00:00.000Z", tenant_id=None,
            )


class TestTenantPinnedVerification(unittest.TestCase):
    def receipt(self, canonical):
        return {
            "canonicalPayload": canonical,
            "actionDescription": "Display",
            "requester": REQUESTER,
            "sigAlg": "AUTO_APPROVED",
        }

    def expected(self, tenant=TENANT):
        result = {
            "target": "target", "actionType": "action", "params": PARAMS, "nonce": "nonce",
            "approvers": {"publicKeys": ["caller-owned-key"]},
        }
        if tenant is not None:
            result["tenantId"] = tenant
        return result

    def verify(self, canonical, expected):
        return verify_approval_receipt(
            self.receipt(canonical), expected, allow_auto_approved=True, allow_expired=True,
            as_of=datetime(2026, 10, 10, tzinfo=timezone.utc),
        )

    def test_v2_requires_exact_independent_tenant(self):
        canonical = canonical_intent_payload(
            "target", "action", "Display", PARAMS, REQUESTER, REQUIREMENT,
            "nonce", "2027-01-01T00:00:00.000Z", tenant_id=TENANT,
        )
        self.assertTrue(self.verify(canonical, self.expected())["ok"])
        self.assertIn("expected tenant", self.verify(canonical, self.expected(None))["reason"])
        self.assertIn("does not match", self.verify(canonical, self.expected("tenant-a"))["reason"])

    def test_v1_remains_valid_only_without_tenant_expectation(self):
        canonical = canonical_intent_payload(
            "target", "action", "Display", PARAMS, REQUESTER, REQUIREMENT,
            "nonce", "2027-01-01T00:00:00.000Z",
        )
        self.assertTrue(self.verify(canonical, self.expected(None))["ok"])
        self.assertIn("not tenant-bound", self.verify(canonical, self.expected())["reason"])
        malformed_v2 = canonical.replace('"v":1', '"v":2')
        self.assertIn("non-empty tenantId", self.verify(malformed_v2, self.expected())["reason"])

    def test_cross_tenant_delegation_is_refused_before_signature_use(self):
        canonical = canonical_offline_intent_payload(
            "target", "action", "Display", PARAMS, REQUESTER, REQUIREMENT, "nonce",
            "2026-10-10T00:00:00.000Z", "2026-10-10T00:15:00.000Z", tenant_id=TENANT,
        )
        result = verify_approval_receipt(
            self.receipt(canonical), self.expected(), allow_offline=True,
            delegation={
                "tenantId": "Tenant-B", "delegatedTo": ["did:intyga:alice"],
                "delegatedQuorum": 1, "target": "target", "actionType": "action",
                "params": PARAMS, "expiresAt": "2026-10-11T00:00:00.000Z",
            },
            as_of=datetime(2026, 10, 10, 0, 1, tzinfo=timezone.utc),
        )
        self.assertFalse(result["ok"])
        self.assertIn("different tenants", result["reason"])


class TestTrustAnchorTenant(unittest.TestCase):
    def test_optional_tenant_is_preserved_and_empty_is_refused(self):
        anchor = {
            "type": "intyga-trust-anchor", "v": 1, "epoch": 1,
            "approvers": [{"did": "did:intyga:key:test", "publicKeys": []}],
        }
        self.assertNotIn("tenantId", parse_trust_anchor_file(json.dumps(anchor)))
        self.assertEqual(
            parse_trust_anchor_file(json.dumps({**anchor, "tenantId": TENANT}))["tenantId"], TENANT
        )
        with self.assertRaisesRegex(InvalidTrustAnchorFile, "non-empty"):
            parse_trust_anchor_file(json.dumps({**anchor, "tenantId": ""}))


if __name__ == "__main__":
    unittest.main()
