"""The approval guard: a wrapped callable must be unrunnable without a human approval.

The client is stubbed — these tests pin the guard's contract (what is sent for approval, what
happens on refusal, and what is verified before the call runs), not the HTTP transport, which
tests/test_client.py covers.
"""

import asyncio
import base64
import unittest
import warnings

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from intyga_sdk.crypto import canonical_intent_payload
from intyga_sdk.errors import ApprovalRefused
from intyga_sdk.guard import require_human_approval

REQUESTER = {"did": "did:intyga:service:agent", "attestation": None}
REQUIREMENT = {
    "requiredApprovals": 1,
    "requireHardwareKey": False,
    "allowedAaguids": [],
    "requesterCannotApprove": False,
    "signerClass": "human",
}


def guard(client, **kwargs):
    """Decorate without the unverified-path warning drowning the suite's output.

    Every call that omits `approvers` warns by design — that is what
    TestUnverifiedPathIsExplicit pins — so the tests exercising the legacy contract silence it here
    rather than each restating it. The warning fires when the DECORATOR is applied, not when the
    factory is called, so the suppression has to wrap that.
    """
    decorator = require_human_approval(client, **kwargs)

    def apply(fn):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            return decorator(fn)

    return apply


class StubClient:
    """Records require_approval calls and answers with a fixed terminal status."""

    def __init__(self, status: str = "APPROVED", receipt=None):
        self.status = status
        self.receipt = receipt
        self.calls = []
        self.consumed = []

    def _resolve_target(self, target):
        return target or "rp-1"

    async def require_approval(self, description, **kwargs):
        self.calls.append({"description": description, **kwargs})
        result = {"status": self.status, "nonce": "nonce-1"}
        if self.receipt is not None:
            result["receipt"] = self.receipt
        return result

    async def consume(self, nonce, action_type, params=None, target=None):
        self.consumed.append({"nonce": nonce, "action_type": action_type, "params": params})
        return {"status": "CONSUMED"}


def signed_receipt(*, target="rp-1", action_type="wipe_database", params, nonce="nonce-1"):
    """A real ES256 receipt over the canonical payload, plus the public key that verifies it."""
    key = ec.generate_private_key(ec.SECP256R1())
    pub = base64.b64encode(
        key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode()
    canonical = canonical_intent_payload(
        target=target,
        action_type=action_type,
        display="Execute wipe_database",
        params=params,
        requester=REQUESTER,
        requirement=REQUIREMENT,
        nonce=nonce,
        expires_at="2999-01-01T00:00:00.000Z",
    )
    receipt = {
        "canonicalPayload": canonical,
        "actionDescription": "Execute wipe_database",
        "requester": REQUESTER,
        "signerDid": "did:intyga:human:alice",
        "signerPublicKey": pub,
        "signature": base64.b64encode(
            key.sign(canonical.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        ).decode(),
        "sigAlg": "ES256",
    }
    return receipt, {"publicKeys": [pub]}


class TestGuardSync(unittest.TestCase):
    def test_approved_runs_the_function_with_the_approved_kwargs(self):
        client = StubClient("APPROVED")

        @guard(client, target="rp-1")
        def wipe_database(*, database: str) -> str:
            return f"wiped {database}"

        self.assertEqual(wipe_database(database="prod-1"), "wiped prod-1")
        self.assertEqual(len(client.calls), 1)
        call = client.calls[0]
        # action_type defaults to the function name — the name a policy rule matches on —
        # and params are the call's kwargs verbatim: what the human signs is what executes.
        self.assertEqual(call["action_type"], "wipe_database")
        self.assertEqual(call["params"], {"database": "prod-1"})
        self.assertEqual(call["target"], "rp-1")

    def test_denied_raises_and_the_function_never_runs(self):
        client = StubClient("DENIED")
        ran = []

        @guard(client, target="rp-1")
        def wipe_database(*, database: str) -> None:
            ran.append(database)

        with self.assertRaises(ApprovalRefused) as ctx:
            wipe_database(database="prod-1")
        self.assertEqual(ctx.exception.status, "DENIED")
        self.assertEqual(ran, [])

    def test_expired_is_a_refusal_too(self):
        client = StubClient("EXPIRED")

        @guard(client, target="rp-1")
        def wipe_database(*, database: str) -> None:
            raise AssertionError("must not run")

        with self.assertRaises(ApprovalRefused) as ctx:
            wipe_database(database="prod-1")
        self.assertEqual(ctx.exception.status, "EXPIRED")

    def test_positional_arguments_are_refused_before_any_approval_is_raised(self):
        client = StubClient("APPROVED")

        @guard(client, target="rp-1")
        def wipe_database(database: str) -> None:
            raise AssertionError("must not run")

        with self.assertRaises(TypeError):
            wipe_database("prod-1")
        # No challenge was created for a call whose parameters could not be named.
        self.assertEqual(client.calls, [])

    def test_explicit_action_type_and_description_are_forwarded(self):
        client = StubClient("APPROVED")

        @guard(client, action_type="wipe_production", description="Wipe it all", target="rp-1")
        def anything(**kwargs) -> str:
            return "ok"

        anything(db="x")
        call = client.calls[0]
        self.assertEqual(call["action_type"], "wipe_production")
        self.assertEqual(call["description"], "Wipe it all")

    def test_sync_guard_inside_a_running_loop_refuses_with_instructions(self):
        client = StubClient("APPROVED")

        @guard(client, target="rp-1")
        def wipe_database(*, database: str) -> None:
            raise AssertionError("must not run")

        async def call_from_loop():
            wipe_database(database="prod-1")

        with self.assertRaises(RuntimeError):
            asyncio.run(call_from_loop())
        self.assertEqual(client.calls, [])


class TestGuardAsync(unittest.TestCase):
    def test_async_function_is_guarded_natively(self):
        client = StubClient("APPROVED")

        @guard(client, target="rp-1")
        async def wipe_database(*, database: str) -> str:
            return f"wiped {database}"

        self.assertEqual(asyncio.run(wipe_database(database="prod-1")), "wiped prod-1")
        self.assertEqual(client.calls[0]["params"], {"database": "prod-1"})

    def test_async_denied_raises_and_never_runs(self):
        client = StubClient("DENIED")

        @guard(client, target="rp-1")
        async def wipe_database(*, database: str) -> None:
            raise AssertionError("must not run")

        with self.assertRaises(ApprovalRefused):
            asyncio.run(wipe_database(database="prod-1"))


class TestVerifiedPath(unittest.TestCase):
    """With `approvers`, the guard is a DIV §5 relying party: it verifies the signature locally
    against keys the CALLER resolved, immediately before the irreversible action. The gateway's
    status string alone is what Invariants 2 and 3 exist to stop anyone relying on."""

    def test_a_verifying_receipt_runs_the_function_and_redeems_the_nonce(self):
        params = {"database": "prod-1"}
        receipt, approvers = signed_receipt(params=params)
        client = StubClient("APPROVED", receipt=receipt)

        @require_human_approval(client, target="rp-1", approvers=approvers)
        def wipe_database(*, database: str) -> str:
            return f"wiped {database}"

        self.assertEqual(wipe_database(database="prod-1"), "wiped prod-1")
        # Redemption is what makes the approval single-use; without it the challenge stays APPROVED
        # and replayable for the rest of its TTL.
        self.assertEqual(
            client.consumed,
            [{"nonce": "nonce-1", "action_type": "wipe_database", "params": params}],
        )

    def test_a_receipt_signed_by_an_untrusted_key_is_refused(self):
        params = {"database": "prod-1"}
        receipt, _ = signed_receipt(params=params)
        _, other_approvers = signed_receipt(params=params)
        client = StubClient("APPROVED", receipt=receipt)

        @require_human_approval(client, target="rp-1", approvers=other_approvers)
        def wipe_database(*, database: str) -> None:
            raise AssertionError("must not run")

        with self.assertRaises(ApprovalRefused) as ctx:
            wipe_database(database="prod-1")
        self.assertEqual(ctx.exception.status, "UNVERIFIED")
        self.assertEqual(client.consumed, [])

    def test_a_receipt_approved_for_different_params_is_refused(self):
        # The whole point of local reconstruction: the payload is rebuilt from the kwargs about to
        # execute, so a gateway swapping the parameters after approval cannot be believed.
        receipt, approvers = signed_receipt(params={"database": "staging-1"})
        client = StubClient("APPROVED", receipt=receipt)

        @require_human_approval(client, target="rp-1", approvers=approvers)
        def wipe_database(*, database: str) -> None:
            raise AssertionError("must not run")

        with self.assertRaises(ApprovalRefused) as ctx:
            wipe_database(database="prod-1")
        self.assertEqual(ctx.exception.status, "UNVERIFIED")

    def test_a_receipt_bound_to_another_target_is_refused(self):
        params = {"database": "prod-1"}
        receipt, approvers = signed_receipt(target="someone-elses-rp", params=params)
        client = StubClient("APPROVED", receipt=receipt)

        @require_human_approval(client, target="rp-1", approvers=approvers)
        def wipe_database(*, database: str) -> None:
            raise AssertionError("must not run")

        with self.assertRaises(ApprovalRefused):
            wipe_database(database="prod-1")

    def test_an_approved_status_with_no_receipt_is_refused(self):
        client = StubClient("APPROVED", receipt=None)

        @require_human_approval(client, target="rp-1", approvers={"publicKeys": ["k"]})
        def wipe_database(*, database: str) -> None:
            raise AssertionError("must not run")

        with self.assertRaises(ApprovalRefused) as ctx:
            wipe_database(database="prod-1")
        self.assertEqual(ctx.exception.status, "UNVERIFIED")
        self.assertIn("no receipt", str(ctx.exception))

    def test_async_verified_path_is_guarded_too(self):
        params = {"database": "prod-1"}
        receipt, approvers = signed_receipt(params=params)
        client = StubClient("APPROVED", receipt=receipt)

        @require_human_approval(client, target="rp-1", approvers=approvers)
        async def wipe_database(*, database: str) -> str:
            return f"wiped {database}"

        self.assertEqual(asyncio.run(wipe_database(database="prod-1")), "wiped prod-1")
        self.assertEqual(len(client.consumed), 1)


class TestUnverifiedPathIsExplicit(unittest.TestCase):
    def test_omitting_approvers_warns_at_decoration_time(self):
        client = StubClient("APPROVED")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")

            @require_human_approval(client, target="rp-1")
            def wipe_database(*, database: str) -> str:
                return f"wiped {database}"

        self.assertEqual(len(caught), 1)
        self.assertIs(caught[0].category, UserWarning)
        self.assertIn("approvers", str(caught[0].message))

    def test_supplying_approvers_does_not_warn(self):
        receipt, approvers = signed_receipt(params={"database": "prod-1"})
        client = StubClient("APPROVED", receipt=receipt)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")

            @require_human_approval(client, target="rp-1", approvers=approvers)
            def wipe_database(*, database: str) -> str:
                return f"wiped {database}"

        self.assertEqual(caught, [])


if __name__ == "__main__":
    unittest.main()
