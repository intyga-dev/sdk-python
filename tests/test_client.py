"""Client contract tests: the nonce merge in require_approval and the typed error split.

Transport is stubbed at intyga_sdk.client._async_request / HTTPX, so these run offline.
"""

import asyncio
import json
import unittest
from unittest import mock

import httpx
import intyga_sdk.client as client_mod
from intyga_sdk.client import IntygaClient
from intyga_sdk.errors import GatewayRefused, GatewayUnreachable


def make_client() -> IntygaClient:
    return IntygaClient(gateway_url="https://gw.example", token="tok", target="rp-1")


class TestRequireApprovalNonce(unittest.TestCase):
    """The one-shot helper must hand back the nonce, or its caller cannot verify the receipt
    (expected["nonce"] is required by verify_approval_receipt) nor record redemption. This was
    the documented dead end of the helper; @intyga/sdk, sdk-go and sdk-rust all merge it."""

    def test_terminal_result_carries_the_nonce(self):
        responses = [
            (200, json.dumps({"nonce": "abc", "status": "PENDING"})),  # POST /authorize
            (200, json.dumps({"status": "APPROVED", "signatureHash": "h"})),  # GET /authorize/abc
        ]

        async def fake_request(url, method="GET", headers=None, json_body=None):
            return responses.pop(0)

        with mock.patch.object(client_mod, "_async_request", fake_request):
            r = asyncio.run(make_client().require_approval("do it", action_type="t"))
        self.assertEqual(r["status"], "APPROVED")
        self.assertEqual(r["nonce"], "abc")

    def test_issued_context_survives_poll(self):
        async def request(url, method="GET", headers=None, json_body=None):
            if method == "POST":
                return 200, json.dumps({"nonce": "ctx", "status": "PENDING", "agentContext": {"nbf": "issued"}})
            return 200, json.dumps({"status": "APPROVED", "agentContext": {"nbf": "wrong"}})
        with mock.patch.object(client_mod, "_async_request", request):
            result = asyncio.run(make_client().require_approval("wire"))
        self.assertEqual(result["agentContext"], {"nbf": "issued"})

    def test_expired_result_carries_the_nonce_too(self):
        async def fake_request(url, method="GET", headers=None, json_body=None):
            if method == "POST":
                return (200, json.dumps({"nonce": "abc", "status": "PENDING"}))
            return (200, json.dumps({"status": "PENDING"}))

        with mock.patch.object(client_mod, "_async_request", fake_request):
            r = asyncio.run(
                make_client().require_approval("do it", action_type="t", timeout_ms=1, interval_ms=1)
            )
        self.assertEqual(r["status"], "EXPIRED")
        self.assertEqual(r["nonce"], "abc")


class TestTypedErrors(unittest.TestCase):
    def test_non_2xx_raises_gateway_refused_with_the_status(self):
        async def fake_request(url, method="GET", headers=None, json_body=None):
            return (402, json.dumps({"error": "protected ops exhausted"}))

        with mock.patch.object(client_mod, "_async_request", fake_request):
            with self.assertRaises(GatewayRefused) as ctx:
                asyncio.run(make_client().authorize("do it", action_type="t"))
        self.assertEqual(ctx.exception.status, 402)
        # The verdict/outage split is load-bearing (DIV §5a): a refusal must never read as
        # unreachability.
        self.assertNotIsInstance(ctx.exception, GatewayUnreachable)

    def test_transport_failure_raises_gateway_unreachable(self):
        class RefusingClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def request(self, method, url, headers=None, json=None):
                raise httpx.ConnectError("connection refused")

        with mock.patch.object(client_mod.httpx, "AsyncClient", return_value=RefusingClient()):
            with self.assertRaises(GatewayUnreachable):
                asyncio.run(client_mod._async_request("https://gw.example/authorize", method="POST"))


class TestGatewayUrlMustBeHttps(unittest.TestCase):
    """I11: a plain-http gateway would carry the bearer token or client secret in the clear, so the
    constructor refuses it before any request exists. Loopback stays usable for a local gateway."""

    def test_refuses_non_https_non_loopback(self):
        for bad in [
            "http://gw.example",
            "http://10.0.0.5:8787",
            "http://128.0.0.1",
            "http://localhost.evil.example",
            "http://127.0.0.1.nip.io",
            "http://[::2]",
            "http://localhost@gw.example",
            "ftp://gw.example",
            "gw.example",
            "",
        ]:
            with self.subTest(url=bad), self.assertRaises(ValueError):
                IntygaClient(gateway_url=bad, token="t", target="rp-1")
        with self.assertRaisesRegex(ValueError, "must use https://"):
            IntygaClient(gateway_url="http://gw.example", token="t", target="rp-1")

    def test_accepts_https_and_loopback(self):
        for ok in [
            "https://gw.example",
            "HTTPS://gw.example",
            "http://localhost:8787",
            "http://LOCALHOST",
            "http://127.0.0.1:8787",
            "http://127.200.3.4",
            "http://[::1]:8787",
        ]:
            with self.subTest(url=ok):
                IntygaClient(gateway_url=ok, token="t", target="rp-1")
        client = IntygaClient(gateway_url="https://gw.example//", token="t", target="rp-1")
        self.assertEqual(client._gateway_url, "https://gw.example")


if __name__ == "__main__":
    unittest.main()
