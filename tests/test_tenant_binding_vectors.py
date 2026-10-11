import json
import unittest
from datetime import datetime
from pathlib import Path

from intyga_sdk.crypto import (
    agent_receipt_digest,
    canonical_agent_authority_payload,
    canonical_delegation_payload,
    canonical_intent_payload,
    canonical_offline_intent_payload,
    canonical_platform_intent_payload,
    verify_agent_authority,
    verify_agent_delegation_chain,
    verify_approval_receipt,
    verify_delegation,
    verify_platform_receipt,
)


V = json.loads(
    (Path(__file__).parents[1] / "vectors" / "tenant-binding-vectors.json").read_text()
)
KEYS = {key["id"]: key for key in V["keys"]}


def at(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def public_anchor(ids):
    return {"publicKeys": [KEYS[key_id]["spkiB64"] for key_id in ids]}


def did_anchor(mapping):
    resolved = {
        did: [KEYS[key_id]["spkiB64"] for key_id in key_ids]
        for did, key_ids in mapping.items()
    }
    return {"dids": list(resolved), "resolveKey": lambda did: resolved.get(did, [])}


def expected(case, field="expected"):
    raw = case[field]
    result = {key: value for key, value in raw.items() if key not in ("approverKeyIds", "approverDids")}
    if "approverKeyIds" in raw:
        result["approvers"] = public_anchor(raw["approverKeyIds"])
    else:
        result["approvers"] = did_anchor(raw["approverDids"])
    return result


def options(case):
    raw = case.get("options", {})
    return {
        "as_of": at(raw["asOf"]),
        **({"expected_origin": raw["expectedOrigin"]} if raw.get("expectedOrigin") else {}),
        **({"allow_offline": True} if raw.get("allowOffline") else {}),
    }


class TestTenantBindingVectors(unittest.TestCase):
    def test_agent_receipt_digest_projection_cases(self):
        for case in V.get("agentReceiptDigestCases", []):
            with self.subTest(case=case["name"]):
                self.assertEqual(agent_receipt_digest(case["receipt"]), case["expected"])

    def test_verifier_cases(self):
        for case in V["cases"]:
            with self.subTest(case=case["name"]):
                tenant_id = case.get("expectedTenantId")
                kwargs = options(case)
                verifier = case["verifier"]
                if verifier == "approval":
                    chain = []
                    for link in case.get("chain", []):
                        link_expected = dict(link["expected"])
                        link_expected["approvers"] = did_anchor(link_expected.pop("approverDids"))
                        if link.get("expectedTenantId") is not None:
                            link_expected["tenantId"] = link["expectedTenantId"]
                        chain.append({"receipt": link["receipt"], "expected": link_expected})
                    result = verify_approval_receipt(
                        case["receipt"], expected(case), expected_tenant_id=tenant_id,
                        agent_authority_chain=chain or None, **kwargs
                    )
                elif verifier == "delegation":
                    result = verify_delegation(
                        case["receipt"], expected(case), expected_tenant_id=tenant_id, **kwargs
                    )
                elif verifier == "authority":
                    result = verify_agent_authority(
                        case["receipt"], expected(case), expected_tenant_id=tenant_id, **kwargs
                    )
                elif verifier == "platform":
                    platform_expected = expected(case)
                    platform_expected["approvers"] = {
                        "publicKeys": [KEYS[key_id]["coseB64"] for key_id in case["expected"]["approverKeyIds"]]
                    }
                    result = verify_platform_receipt(
                        case["receipt"], platform_expected, expected_tenant_id=tenant_id, **kwargs
                    )
                elif verifier == "approval-with-delegation":
                    delegation_result = verify_delegation(
                        case["delegationReceipt"], expected(case, "delegationExpected"),
                        expected_tenant_id=case.get("delegationExpectedTenantId"),
                        as_of=kwargs["as_of"],
                    )
                    self.assertTrue(delegation_result["ok"], delegation_result.get("reason"))
                    result = verify_approval_receipt(
                        case["receipt"], expected(case), delegation=delegation_result["delegation"],
                        expected_tenant_id=tenant_id, **kwargs
                    )
                elif verifier == "authority-chain":
                    chain = []
                    for link in case["chain"]:
                        link_expected = dict(link["expected"])
                        link_expected["approvers"] = did_anchor(link_expected.pop("approverDids"))
                        if link.get("expectedTenantId") is not None:
                            link_expected["tenantId"] = link["expectedTenantId"]
                        chain.append({"receipt": link["receipt"], "expected": link_expected})
                    result = verify_agent_delegation_chain(
                        chain, case["action"], as_of=kwargs["as_of"]
                    )
                else:
                    self.fail(f"unknown verifier {verifier}")
                self.assertEqual(result["ok"], case["ok"], result.get("reason"))

    def test_invalid_builder_tenants(self):
        requester = {"did": "did:intyga:service:test", "attestation": None}
        requirement = {
            "requiredApprovals": 1, "requireHardwareKey": False, "allowedAaguids": [],
            "requesterCannotApprove": False, "signerClass": "human",
        }
        for tenant_id in V["invalidBuilderTenantIds"]:
            builders = (
                lambda: canonical_intent_payload("t", "a", "d", {}, requester, requirement, "n", "2027-01-01T00:00:00.000Z", tenant_id=tenant_id),
                lambda: canonical_offline_intent_payload("t", "a", "d", {}, requester, requirement, "n", "2026-01-01T00:00:00.000Z", "2026-01-01T00:15:00.000Z", tenant_id=tenant_id),
                lambda: canonical_delegation_payload("t", "a", "d", {}, requester, requirement, ["did:intyga:a"], 1, "n", "2026-01-01T00:00:00.000Z", "2026-01-02T00:00:00.000Z", tenant_id=tenant_id),
                lambda: canonical_agent_authority_payload("t", ["a"], "d", {"did": "did:intyga:agent"}, requester, requirement, "n", "2026-01-01T00:00:00.000Z", "2026-01-02T00:00:00.000Z", tenant_id=tenant_id),
                lambda: canonical_platform_intent_payload("a" * 64, "example.com", "s", "2026-01-01T00:00:00.000Z", "2026-01-01T00:05:00.000Z", "n", tenant_id=tenant_id),
            )
            for build in builders:
                with self.subTest(tenant_id=tenant_id, builder=build):
                    with self.assertRaises(ValueError):
                        build()


if __name__ == "__main__":
    unittest.main()
