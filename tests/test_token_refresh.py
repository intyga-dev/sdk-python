"""Token lifecycle: the client-credentials exchange, its `expires_in`-driven re-exchange, the
single 401 retry, and the stored `intyga login` credential that cannot be refreshed.

Transport is stubbed at intyga_sdk.client._async_request and the clock at time.monotonic (the
module the client reads it from), so these run offline and without sleeping. The fake clock only
ever moves forward — asyncio's event loop reads the same monotonic clock.
"""

import asyncio
import base64
import json
import time
import unittest
from unittest import mock

import intyga_sdk.client as client_mod
from intyga_sdk.client import IntygaClient, _decode_jwt_exp
from intyga_sdk.errors import GatewayRefused

GW = "https://gw.example"


class FakeClock:
    """time.monotonic() stand-in: an exact base plus an offset the test advances."""

    def __init__(self):
        # Keep the base exactly representable. A fractional real monotonic snapshot made the
        # boundary assertion compare `base + 840` with `(base + 900) - 60`; depending on the
        # snapshot, the second expression can be one ULP larger and keep the token cached for a
        # fraction of a nanosecond. That made identical CI jobs disagree about the exact boundary.
        self._base = 1_000_000.0
        self.offset = 0.0

    def __call__(self) -> float:
        return self._base + self.offset


class FakeGateway:
    """Records every request; hands out access tokens `t1`, `t2`, ... per exchange and answers
    the authenticated routes from a per-route queue of (status, body) or a default 200."""

    def __init__(self, expires_in=900, authed_responses=None):
        self.expires_in = expires_in
        self.calls = []  # (path, method, bearer-or-basic)
        self.exchanges = 0
        self.authed_responses = list(authed_responses or [])

    async def __call__(self, url, method="GET", headers=None, json_body=None):
        headers = headers or {}
        path = url[len(GW):]
        self.calls.append((path, method, headers.get("authorization")))
        if path == "/oauth/token":
            self.exchanges += 1
            body = {"access_token": f"t{self.exchanges}"}
            if self.expires_in is not None:
                body["expires_in"] = self.expires_in
            return (200, json.dumps(body))
        if self.authed_responses:
            return self.authed_responses.pop(0)
        return (200, json.dumps({"nonce": "n1", "status": "PENDING"}))

    def bearers(self, path):
        return [auth for (p, _m, auth) in self.calls if p == path]


def exchanging_client(**kw) -> IntygaClient:
    return IntygaClient(gateway_url=GW, client_id="cid", client_secret="sec", target="rp-1", **kw)


def fake_jwt(claims: dict) -> str:
    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8"))
    return f"{header}.{b64(json.dumps(claims).encode('utf-8'))}.{b64(b'not-a-real-signature')}"


class TestExchangeAndCache(unittest.TestCase):
    def test_exchange_uses_basic_auth_and_caches_the_token(self):
        gw = FakeGateway(expires_in=900)
        client = exchanging_client()
        with mock.patch.object(client_mod, "_async_request", gw):
            asyncio.run(client.authorize("do it", action_type="t"))
            asyncio.run(client.authorize("do it", action_type="t"))
        self.assertEqual(gw.exchanges, 1)
        expected_basic = "Basic " + base64.b64encode(b"cid:sec").decode("ascii")
        self.assertEqual(gw.bearers("/oauth/token"), [expected_basic])
        self.assertEqual(gw.bearers("/authorize"), ["Bearer t1", "Bearer t1"])

    def test_failed_exchange_raises_gateway_refused_with_the_status(self):
        async def fake_request(url, method="GET", headers=None, json_body=None):
            return (401, json.dumps({"error": "invalid_client"}))

        with mock.patch.object(client_mod, "_async_request", fake_request):
            with self.assertRaises(GatewayRefused) as ctx:
                asyncio.run(exchanging_client().token())
        self.assertEqual(ctx.exception.status, 401)

    def test_re_exchanges_once_the_clock_passes_expires_in_minus_margin(self):
        # expires_in 900 → margin min(60, 90) = 60 → fresh strictly before 840 s.
        gw = FakeGateway(expires_in=900)
        clock = FakeClock()
        client = exchanging_client()
        with mock.patch.object(client_mod, "_async_request", gw), mock.patch.object(
            client_mod.time, "monotonic", clock
        ):
            asyncio.run(client.authorize("do it", action_type="t"))
            clock.offset = 839.0
            asyncio.run(client.authorize("do it", action_type="t"))
            self.assertEqual(gw.exchanges, 1, "inside the margin the cache is served")
            clock.offset = 840.0
            asyncio.run(client.authorize("do it", action_type="t"))
            self.assertEqual(gw.exchanges, 2, "at expires_in - margin the token is re-exchanged")
            clock.offset = 841.0
            asyncio.run(client.authorize("do it", action_type="t"))
            self.assertEqual(gw.exchanges, 2, "the fresh token is cached in turn")
        self.assertEqual(gw.bearers("/authorize"), ["Bearer t1", "Bearer t1", "Bearer t2", "Bearer t2"])

    def test_margin_scales_down_for_a_short_lived_token(self):
        # expires_in 100 → margin min(60, 10) = 10 → fresh strictly before 90 s.
        gw = FakeGateway(expires_in=100)
        clock = FakeClock()
        client = exchanging_client()
        with mock.patch.object(client_mod, "_async_request", gw), mock.patch.object(
            client_mod.time, "monotonic", clock
        ):
            asyncio.run(client.status("n1"))
            clock.offset = 89.0
            asyncio.run(client.status("n1"))
            self.assertEqual(gw.exchanges, 1)
            clock.offset = 90.0
            asyncio.run(client.status("n1"))
            self.assertEqual(gw.exchanges, 2)

    def test_absent_expires_in_means_one_exchange_for_the_life_of_the_process(self):
        gw = FakeGateway(expires_in=None)
        clock = FakeClock()
        client = exchanging_client()
        with mock.patch.object(client_mod, "_async_request", gw), mock.patch.object(
            client_mod.time, "monotonic", clock
        ):
            for offset in (0.0, 3600.0, 86400.0):
                clock.offset = offset
                asyncio.run(client.authorize("do it", action_type="t"))
        self.assertEqual(gw.exchanges, 1)

    def test_non_numeric_expires_in_is_treated_as_absent(self):
        for bad in ("900", True, -5, 0):
            with self.subTest(expires_in=bad):
                gw = FakeGateway(expires_in=bad)
                clock = FakeClock()
                client = exchanging_client()
                with mock.patch.object(client_mod, "_async_request", gw), mock.patch.object(
                    client_mod.time, "monotonic", clock
                ):
                    asyncio.run(client.status("n1"))
                    clock.offset = 100000.0
                    asyncio.run(client.status("n1"))
                self.assertEqual(gw.exchanges, 1)
                self.assertIsNone(client._cached_expires_at)

    def test_long_poll_re_exchanges_per_iteration(self):
        """require_approval calls token() on every poll, so a wait longer than the token's life
        keeps going on a fresh token instead of dying at expiry — the guard's long-lived client
        depends on exactly this."""
        gw = FakeGateway(
            expires_in=100,
            authed_responses=[
                (200, json.dumps({"nonce": "n1", "status": "PENDING"})),  # POST /authorize
                (200, json.dumps({"status": "PENDING"})),  # GET at t=0
                (200, json.dumps({"status": "APPROVED"})),  # GET at t=95, on the new token
            ],
        )
        clock = FakeClock()
        client = exchanging_client()
        real_sleep = asyncio.sleep

        async def advancing_sleep(_seconds):
            clock.offset += 95.0
            await real_sleep(0)

        with mock.patch.object(client_mod, "_async_request", gw), mock.patch.object(
            client_mod.time, "monotonic", clock
        ), mock.patch.object(client_mod.asyncio, "sleep", advancing_sleep):
            r = asyncio.run(client.require_approval("do it", action_type="t", timeout_ms=10_000_000))
        self.assertEqual(r["status"], "APPROVED")
        self.assertEqual(gw.exchanges, 2)
        self.assertEqual(gw.bearers("/authorize/n1"), ["Bearer t1", "Bearer t2"])


class TestUnauthorizedRetry(unittest.TestCase):
    def test_401_then_200_re_exchanges_exactly_once(self):
        gw = FakeGateway(
            expires_in=900,
            authed_responses=[
                (401, json.dumps({"error": "Invalid token: ERR_JWT_EXPIRED"})),
                (200, json.dumps({"nonce": "n1", "status": "PENDING"})),
            ],
        )
        client = exchanging_client()
        with mock.patch.object(client_mod, "_async_request", gw):
            r = asyncio.run(client.authorize("do it", action_type="t"))
        self.assertEqual(r["nonce"], "n1")
        self.assertEqual(gw.exchanges, 2)
        self.assertEqual(
            [(p, auth) for (p, _m, auth) in gw.calls],
            [
                ("/oauth/token", mock.ANY),
                ("/authorize", "Bearer t1"),
                ("/oauth/token", mock.ANY),
                ("/authorize", "Bearer t2"),
            ],
        )

    def test_consume_and_status_retry_the_same_way(self):
        for name, call in (
            ("consume", lambda c: c.consume("n1", "t", params={"a": 1})),
            ("status", lambda c: c.status("n1")),
        ):
            with self.subTest(op=name):
                gw = FakeGateway(
                    expires_in=900,
                    authed_responses=[(401, "{}"), (200, json.dumps({"ok": True, "status": "APPROVED"}))],
                )
                client = exchanging_client()
                with mock.patch.object(client_mod, "_async_request", gw):
                    asyncio.run(call(client))
                self.assertEqual(gw.exchanges, 2)
                authed = [(p, auth) for (p, _m, auth) in gw.calls if p != "/oauth/token"]
                self.assertEqual([auth for (_p, auth) in authed], ["Bearer t1", "Bearer t2"])

    def test_a_second_401_is_the_verdict(self):
        gw = FakeGateway(expires_in=900, authed_responses=[(401, "{}"), (401, "{}"), (200, "{}")])
        client = exchanging_client()
        with mock.patch.object(client_mod, "_async_request", gw):
            with self.assertRaises(GatewayRefused) as ctx:
                asyncio.run(client.authorize("do it", action_type="t"))
        self.assertEqual(ctx.exception.status, 401)
        self.assertEqual(gw.exchanges, 2, "retried once, never looped")
        self.assertEqual(len(gw.bearers("/authorize")), 2)

    def test_other_refusals_are_not_retried(self):
        gw = FakeGateway(expires_in=900, authed_responses=[(403, json.dumps({"error": "policy"}))])
        client = exchanging_client()
        with mock.patch.object(client_mod, "_async_request", gw):
            with self.assertRaises(GatewayRefused) as ctx:
                asyncio.run(client.authorize("do it", action_type="t"))
        self.assertEqual(ctx.exception.status, 403)
        self.assertEqual(gw.exchanges, 1)

    def test_explicit_token_is_never_re_exchanged(self):
        gw = FakeGateway(expires_in=900, authed_responses=[(401, "{}")])
        client = IntygaClient(gateway_url=GW, token="explicit", client_id="cid", client_secret="sec", target="rp-1")
        with mock.patch.object(client_mod, "_async_request", gw):
            with self.assertRaises(GatewayRefused) as ctx:
                asyncio.run(client.authorize("do it", action_type="t"))
        self.assertEqual(ctx.exception.status, 401)
        self.assertEqual(gw.exchanges, 0)
        self.assertEqual(gw.bearers("/authorize"), ["Bearer explicit"])


class TestStoredCredential(unittest.TestCase):
    """An `intyga login` credential has no secret behind it: the SDK can neither refresh it nor
    retry with it, so the failure must name the fix rather than surface a bare 401."""

    def test_expired_stored_credential_raises_before_any_request(self):
        expired = fake_jwt({"sub": "did:key:z1", "exp": int(time.time()) - 60})
        gw = FakeGateway()
        client = IntygaClient(gateway_url=GW, allow_stored_credentials=True, target="rp-1")
        with mock.patch.object(client_mod, "_load_stored_token", lambda _gw: expired), mock.patch.object(
            client_mod, "_async_request", gw
        ):
            with self.assertRaises(GatewayRefused) as ctx:
                asyncio.run(client.authorize("do it", action_type="t"))
        self.assertEqual(ctx.exception.status, 401)
        self.assertIn("intyga login", str(ctx.exception))
        self.assertEqual(gw.calls, [])

    def test_live_stored_credential_is_used_and_cached(self):
        live = fake_jwt({"sub": "did:key:z1", "exp": int(time.time()) + 600})
        gw = FakeGateway()
        client = IntygaClient(gateway_url=GW, allow_stored_credentials=True, target="rp-1")
        loads = []

        def load(_gw):
            loads.append(1)
            return live

        with mock.patch.object(client_mod, "_load_stored_token", load), mock.patch.object(
            client_mod, "_async_request", gw
        ):
            asyncio.run(client.status("n1"))
            asyncio.run(client.status("n1"))
        self.assertEqual(gw.exchanges, 0)
        self.assertEqual(gw.bearers("/authorize/n1"), [f"Bearer {live}", f"Bearer {live}"])
        self.assertEqual(len(loads), 1)
        self.assertEqual(client._cached_source, "stored")
        # The wall-clock `exp` is mapped onto the monotonic clock so a credential that lapses
        # mid-process is re-read (and refused with the authored error) instead of served stale.
        self.assertAlmostEqual(client._cached_expires_at - time.monotonic(), 600.0, delta=5.0)

    def test_stored_credential_401_is_an_authored_error_not_a_retry(self):
        live = fake_jwt({"sub": "did:key:z1", "exp": int(time.time()) + 600})
        gw = FakeGateway(authed_responses=[(401, json.dumps({"error": "Invalid token"}))])
        client = IntygaClient(gateway_url=GW, allow_stored_credentials=True, target="rp-1")
        with mock.patch.object(client_mod, "_load_stored_token", lambda _gw: live), mock.patch.object(
            client_mod, "_async_request", gw
        ):
            with self.assertRaises(GatewayRefused) as ctx:
                asyncio.run(client.authorize("do it", action_type="t"))
        self.assertEqual(ctx.exception.status, 401)
        self.assertIn("intyga login", str(ctx.exception))
        self.assertEqual(gw.exchanges, 0)
        self.assertEqual(len(gw.bearers("/authorize")), 1, "nothing to retry with")
        self.assertIsNone(client._cached_token, "cleared so a fresh login is picked up next call")

    def test_401_retry_re_exchanges_with_client_credentials_never_the_stored_token(self):
        # SECURITY REGRESSION: the retry used to go back through token(), which consults
        # ~/.intyga/credentials.json BEFORE the client-credentials branch. A process holding client
        # credentials on a box where someone ran `intyga login` mid-session would retry an AGENT call
        # as the HUMAN — a different principal and a different requester on the witness leaf.
        live = fake_jwt({"sub": "did:key:human", "exp": int(time.time()) + 600})
        on_disk = {"token": None}
        gw = FakeGateway(
            expires_in=900,
            authed_responses=[
                (401, json.dumps({"error": "Invalid token: ERR_JWT_EXPIRED"})),
                (200, json.dumps({"nonce": "n1", "status": "PENDING"})),
            ],
        )
        real_gw = gw

        async def gateway(url, method="GET", headers=None, json_body=None):
            status, body = await real_gw(url, method=method, headers=headers, json_body=json_body)
            if status == 401:
                # A concurrent `intyga login` lands exactly between the first exchange and its 401.
                on_disk["token"] = live
            return status, body

        client = exchanging_client(allow_stored_credentials=True)
        with mock.patch.object(client_mod, "_load_stored_token", lambda _gw: on_disk["token"]), mock.patch.object(
            client_mod, "_async_request", gateway
        ):
            r = asyncio.run(client.authorize("do it", action_type="t"))
        self.assertEqual(r["nonce"], "n1")
        self.assertEqual(gw.exchanges, 2, "the retry must be a client-credentials exchange")
        self.assertEqual(gw.bearers("/authorize"), ["Bearer t1", "Bearer t2"])
        self.assertNotIn(f"Bearer {live}", gw.bearers("/authorize"), "the stored human token must never be sent")

    def test_stored_credential_without_a_readable_exp_is_still_used(self):
        opaque = "not-a-jwt"
        gw = FakeGateway()
        client = IntygaClient(gateway_url=GW, allow_stored_credentials=True, target="rp-1")
        with mock.patch.object(client_mod, "_load_stored_token", lambda _gw: opaque), mock.patch.object(
            client_mod, "_async_request", gw
        ):
            asyncio.run(client.status("n1"))
        self.assertEqual(gw.bearers("/authorize/n1"), ["Bearer not-a-jwt"])
        self.assertIsNone(client._cached_expires_at)


class TestDecodeJwtExp(unittest.TestCase):
    def test_reads_exp_from_an_unpadded_base64url_payload(self):
        self.assertEqual(_decode_jwt_exp(fake_jwt({"exp": 1700000000})), 1700000000.0)
        self.assertEqual(_decode_jwt_exp(fake_jwt({"exp": 1700000000.5, "x": "é"})), 1700000000.5)

    def test_is_none_for_anything_it_cannot_read(self):
        for token in ("", "a.b", "a.b.c.d", "x.!!!.y", fake_jwt({}), fake_jwt({"exp": "soon"}), fake_jwt({"exp": True})):
            with self.subTest(token=token):
                self.assertIsNone(_decode_jwt_exp(token))


if __name__ == "__main__":
    unittest.main()
