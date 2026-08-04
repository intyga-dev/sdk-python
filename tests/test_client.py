"""Client contract tests: the nonce merge in require_approval and the typed error split.

Transport is stubbed at intyga_sdk.client._async_request / urllib, so these run offline.
"""

import asyncio
import json
import unittest
import urllib.error
from unittest import mock

import intyga_sdk.client as client_mod
from intyga_sdk.client import IntygaClient, _sync_request
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
        def fake_urlopen(req):
            raise urllib.error.URLError("connection refused")

        with mock.patch.object(client_mod.urllib.request, "urlopen", fake_urlopen):
            with self.assertRaises(GatewayUnreachable):
                _sync_request("https://gw.example/authorize", method="POST")


if __name__ == "__main__":
    unittest.main()
