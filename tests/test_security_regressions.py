"""Regressions for approval-flow composition and authenticated transport boundaries."""

import asyncio
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import intyga_sdk.client as client_mod
from intyga_sdk.client import IntygaClient
from intyga_sdk.errors import GatewayRefused, GatewayResponseUnreadable, GatewayUnreachable
from intyga_sdk.guard import require_human_approval

from test_guard import signed_receipt


class TestGuardArgumentSnapshot(unittest.TestCase):
    def test_nested_mutation_during_consume_cannot_change_execution(self):
        original = {"transfer": {"amount": 10, "tags": ["ordinary"]}}
        receipt, approvers = signed_receipt(params={"payload": original})
        consume_started = asyncio.Event()
        mutation_done = asyncio.Event()
        consumed = []
        executed = []

        class PendingConsumeClient:
            def _resolve_target(self, target):
                return target or "rp-1"

            async def require_approval(self, description, **kwargs):
                return {"status": "APPROVED", "nonce": "nonce-1", "receipt": receipt}

            async def consume(self, nonce, action_type, params=None, target=None):
                consumed.append(params["payload"]["transfer"]["amount"])
                consume_started.set()
                await mutation_done.wait()
                return {"status": "CONSUMED"}

        @require_human_approval(PendingConsumeClient(), target="rp-1", approvers=approvers)
        async def wipe_database(*, payload):
            executed.append(payload["transfer"]["amount"])

        async def scenario():
            async def mutate_shared_input():
                await consume_started.wait()
                original["transfer"]["amount"] = 1_000_000
                original["transfer"]["tags"].append("replaced")
                mutation_done.set()

            mutation = asyncio.create_task(mutate_shared_input())
            await wipe_database(payload=original)
            await mutation

        asyncio.run(scenario())
        self.assertEqual(consumed, [10])
        self.assertEqual(executed, [10])
        self.assertEqual(original["transfer"]["amount"], 1_000_000)

    def test_non_json_kwargs_are_refused_before_client_await(self):
        class NeverCalledClient:
            calls = 0

            async def require_approval(self, description, **kwargs):
                self.calls += 1
                raise AssertionError("must not create a challenge")

        client = NeverCalledClient()

        @require_human_approval(client, target="rp-1", approvers={"publicKeys": ["unused"]})
        async def operation(*, value):
            raise AssertionError("must not execute")

        with self.assertRaises(ValueError):
            asyncio.run(operation(value=float("nan")))
        self.assertEqual(client.calls, 0)


class TestAuthenticatedRedirects(unittest.TestCase):
    def _servers(self):
        captured = []

        class Sink(BaseHTTPRequestHandler):
            def do_GET(self):
                captured.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()

            do_POST = do_GET

            def log_message(self, format, *args):
                pass

        sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)

        class Redirect(BaseHTTPRequestHandler):
            def _redirect(self):
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{sink.server_port}/capture")
                self.end_headers()

            do_GET = _redirect
            do_POST = _redirect

            def log_message(self, format, *args):
                pass

        redirect = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        for server in (sink, redirect):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        return captured, sink, redirect

    def test_basic_token_exchange_redirect_is_refused_without_forwarding(self):
        captured, sink, redirect = self._servers()
        try:
            client = IntygaClient(
                f"http://127.0.0.1:{redirect.server_port}",
                client_id="client",
                client_secret="secret",
                target="rp-1",
            )
            with self.assertRaises(GatewayRefused) as ctx:
                asyncio.run(client.token())
            self.assertEqual(ctx.exception.status, 302)
            self.assertEqual(captured, [])
        finally:
            redirect.shutdown()
            sink.shutdown()
            redirect.server_close()
            sink.server_close()

    def test_bearer_redirect_is_refused_without_forwarding(self):
        captured, sink, redirect = self._servers()
        try:
            client = IntygaClient(
                f"http://127.0.0.1:{redirect.server_port}", token="bearer-secret", target="rp-1"
            )
            with self.assertRaises(GatewayRefused) as ctx:
                asyncio.run(client.status("nonce"))
            self.assertEqual(ctx.exception.status, 302)
            self.assertEqual(captured, [])
        finally:
            redirect.shutdown()
            sink.shutdown()
            redirect.server_close()
            sink.server_close()


class TestRequestShapeAndDeadlines(unittest.TestCase):
    def test_authorize_omits_unset_action_type_and_preserves_explicit_value(self):
        bodies = []

        async def transport(url, method="GET", headers=None, json_body=None):
            bodies.append(json_body)
            return 200, json.dumps({"nonce": "n1"})

        with mock.patch.object(client_mod, "_async_request", transport):
            asyncio.run(IntygaClient("https://gw", token="t", target="rp").authorize("one"))
            asyncio.run(
                IntygaClient("https://gw", token="t", target="rp").authorize(
                    "two", action_type="transfer"
                )
            )
        self.assertNotIn("actionType", bodies[0])
        self.assertEqual(bodies[1]["actionType"], "transfer")

    def test_timeout_seconds_controls_both_ttl_and_a_121_second_wait(self):
        sent = []
        clock = [1_000.0]

        async def transport(url, method="GET", headers=None, json_body=None):
            if method == "POST":
                sent.append(json_body["timeout"])
                return 200, json.dumps({"nonce": "n1"})
            clock[0] += 121.0
            return 200, json.dumps({"status": "APPROVED"})

        with mock.patch.object(client_mod, "_async_request", transport), mock.patch.object(
            client_mod, "_monotonic", side_effect=lambda: clock[0]
        ):
            result = asyncio.run(
                IntygaClient("https://gw", token="t", target="rp").require_approval(
                    "transfer", timeout=600
                )
            )
        self.assertEqual(sent, [600])
        self.assertEqual(result["status"], "APPROVED")

    def test_timeout_ms_takes_precedence_and_late_approval_is_expired(self):
        sent = []
        clock = [10.0]

        async def transport(url, method="GET", headers=None, json_body=None):
            if method == "POST":
                sent.append(json_body["timeout"])
                return 200, json.dumps({"nonce": "n1"})
            clock[0] += 2.0
            return 200, json.dumps({"status": "APPROVED"})

        with mock.patch.object(client_mod, "_async_request", transport), mock.patch.object(
            client_mod, "_monotonic", side_effect=lambda: clock[0]
        ):
            result = asyncio.run(
                IntygaClient("https://gw", token="t", target="rp").require_approval(
                    "transfer", timeout=600, timeout_ms=1_500
                )
            )
        self.assertEqual(sent, [2])
        self.assertEqual(result, {"status": "EXPIRED", "nonce": "n1"})

    def _slow_server(self, mode):
        accepted = threading.Event()
        first_body_byte = threading.Event()

        class SlowHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                accepted.set()
                if mode == "headers":
                    time.sleep(1.5)
                    self.send_response(200)
                    self.end_headers()
                    return

                body = b'{"error":"slow refusal body"}'
                self.send_response(402 if mode == "error-body" else 200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    for byte in body:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        first_body_byte.set()
                        time.sleep(0.08)  # progress defeats an inactivity-only read timeout
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, accepted, first_body_byte

    def test_slow_headers_and_trickling_bodies_obey_total_wall_clock_deadline(self):
        # Each case exercises a real async socket. In particular, the error body must be read before
        # GatewayRefused can include it, so it needs the same whole-request bound as a 2xx body.
        for mode in ("headers", "body", "error-body"):
            with self.subTest(mode=mode):
                server, accepted, first_body_byte = self._slow_server(mode)
                try:
                    client = IntygaClient(
                        f"http://127.0.0.1:{server.server_port}", token="token", target="rp"
                    )
                    started = time.monotonic()
                    # Before the headers, no response exists: an outage. After them, the gateway
                    # answered and only its body was lost — never an outage, so never routed
                    # offline (DIV §5a).
                    expected = GatewayUnreachable if mode == "headers" else GatewayResponseUnreadable
                    with self.assertRaises(expected):
                        asyncio.run(client.require_approval("transfer", timeout_ms=300))
                    elapsed = time.monotonic() - started
                    self.assertTrue(accepted.is_set(), f"{mode} timed out before the server accepted")
                    if mode != "headers":
                        self.assertTrue(
                            first_body_byte.is_set(), f"{mode} timed out before response streaming"
                        )
                    self.assertLess(elapsed, 0.80, f"{mode} exceeded total deadline: {elapsed}")
                    self.assertFalse(
                        any(thread.name.startswith("asyncio_") for thread in threading.enumerate()),
                        "async transport must not strand default-executor workers",
                    )
                finally:
                    server.shutdown()
                    server.server_close()

    def test_invalid_durations_are_rejected_before_transport(self):
        client = IntygaClient("https://gw", token="token", target="rp")
        for kwargs in (
            {"timeout_ms": 0},
            {"timeout_ms": -1},
            {"timeout_ms": float("inf")},
            {"timeout_ms": float("nan")},
            {"interval_ms": 0},
            {"interval_ms": -1},
            {"interval_ms": float("inf")},
            {"interval_ms": float("nan")},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                asyncio.run(client.require_approval("transfer", **kwargs))


if __name__ == "__main__":
    unittest.main()
