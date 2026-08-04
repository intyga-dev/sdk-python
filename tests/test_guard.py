"""The approval guard: a wrapped callable must be unrunnable without a human approval.

The client is stubbed — these tests pin the guard's contract (what is sent for approval, what
happens on refusal), not the HTTP transport, which tests/test_client.py covers.
"""

import asyncio
import unittest

from intyga_sdk.errors import ApprovalRefused
from intyga_sdk.guard import require_human_approval


class StubClient:
    """Records require_approval calls and answers with a fixed terminal status."""

    def __init__(self, status: str = "APPROVED"):
        self.status = status
        self.calls = []

    async def require_approval(self, description, **kwargs):
        self.calls.append({"description": description, **kwargs})
        return {"status": self.status, "nonce": "nonce-1"}


class TestGuardSync(unittest.TestCase):
    def test_approved_runs_the_function_with_the_approved_kwargs(self):
        client = StubClient("APPROVED")

        @require_human_approval(client, target="rp-1")
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

        @require_human_approval(client, target="rp-1")
        def wipe_database(*, database: str) -> None:
            ran.append(database)

        with self.assertRaises(ApprovalRefused) as ctx:
            wipe_database(database="prod-1")
        self.assertEqual(ctx.exception.status, "DENIED")
        self.assertEqual(ran, [])

    def test_expired_is_a_refusal_too(self):
        client = StubClient("EXPIRED")

        @require_human_approval(client, target="rp-1")
        def wipe_database(*, database: str) -> None:
            raise AssertionError("must not run")

        with self.assertRaises(ApprovalRefused) as ctx:
            wipe_database(database="prod-1")
        self.assertEqual(ctx.exception.status, "EXPIRED")

    def test_positional_arguments_are_refused_before_any_approval_is_raised(self):
        client = StubClient("APPROVED")

        @require_human_approval(client, target="rp-1")
        def wipe_database(database: str) -> None:
            raise AssertionError("must not run")

        with self.assertRaises(TypeError):
            wipe_database("prod-1")
        # No challenge was created for a call whose parameters could not be named.
        self.assertEqual(client.calls, [])

    def test_explicit_action_type_and_description_are_forwarded(self):
        client = StubClient("APPROVED")

        @require_human_approval(
            client, action_type="wipe_production", description="Wipe it all", target="rp-1"
        )
        def anything(**kwargs) -> str:
            return "ok"

        anything(db="x")
        call = client.calls[0]
        self.assertEqual(call["action_type"], "wipe_production")
        self.assertEqual(call["description"], "Wipe it all")

    def test_sync_guard_inside_a_running_loop_refuses_with_instructions(self):
        client = StubClient("APPROVED")

        @require_human_approval(client, target="rp-1")
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

        @require_human_approval(client, target="rp-1")
        async def wipe_database(*, database: str) -> str:
            return f"wiped {database}"

        self.assertEqual(asyncio.run(wipe_database(database="prod-1")), "wiped prod-1")
        self.assertEqual(client.calls[0]["params"], {"database": "prod-1"})

    def test_async_denied_raises_and_never_runs(self):
        client = StubClient("DENIED")

        @require_human_approval(client, target="rp-1")
        async def wipe_database(*, database: str) -> None:
            raise AssertionError("must not run")

        with self.assertRaises(ApprovalRefused):
            asyncio.run(wipe_database(database="prod-1"))


if __name__ == "__main__":
    unittest.main()
