import asyncio
import base64
import contextvars
import json
import math
import ssl
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

from .errors import GatewayRefused, GatewayUnreachable

# A cached exchange is served only while more than this remains of the lifetime the gateway
# advertised in `expires_in`; past it the client re-exchanges BEFORE the token can 401 mid-poll.
# The margin is min(60 s, expires_in / 10), so a short-lived token is not re-exchanged on every call.
_REFRESH_MARGIN_MAX_SECONDS = 60.0
_DEFAULT_APPROVAL_TIMEOUT_MS = 120_000

# Set only around require_approval(), so token exchange and every authenticated request share one
# total monotonic deadline without adding a second, independently drifting timeout parameter to
# each public method.
_request_deadline: contextvars.ContextVar[Optional[float]] = contextvars.ContextVar(
    "intyga_request_deadline", default=None
)


def _monotonic() -> float:
    """Clock seam for deterministic deadline tests; production always uses the monotonic clock."""
    return time.monotonic()

_STORED_CREDENTIAL_EXPIRED = (
    "the stored credential from `intyga login` has expired and cannot be refreshed by the SDK "
    "(it has no client secret) — run `intyga login` again"
)
_STORED_CREDENTIAL_REJECTED = (
    "the gateway rejected the stored credential from `intyga login` (401; it has most likely "
    "expired, and the SDK cannot refresh it) — run `intyga login` again"
)


def _refresh_margin(expires_in: float) -> float:
    return min(_REFRESH_MARGIN_MAX_SECONDS, expires_in / 10.0)


def _numeric_expires_in(value: Any) -> Optional[float]:
    """`expires_in` as seconds, or None when absent, non-numeric or non-positive — meaning "no
    expiry known", in which case the token is cached until the gateway refuses it."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or value <= 0:
        return None
    return float(value)


def _decode_jwt_exp(token: str) -> Optional[float]:
    """Read `exp` (Unix seconds) out of a JWT payload WITHOUT verifying anything.

    A hint, never a trust decision: the gateway is what verifies the signature. This exists so a
    stored `intyga login` credential can say "expired, log in again" instead of surfacing a bare
    401 — base64url with the padding the JWT profile strips, and None for anything that is not a
    three-part token carrying a numeric `exp`.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        padded = payload + "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        exp = claims.get("exp") if isinstance(claims, dict) else None
        if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not math.isfinite(exp):
            return None
        return float(exp)
    except Exception:
        return None


def _load_stored_token(gateway_url: str) -> Optional[str]:
    try:
        creds_path = Path.home() / ".intyga" / "credentials.json"
        if creds_path.is_file():
            with open(creds_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get(gateway_url)
    except Exception:
        pass
    return None

def _remaining_request_seconds() -> Optional[float]:
    deadline = _request_deadline.get()
    if deadline is None:
        return None
    return max(0.001, deadline - _monotonic())


async def _async_request(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, json_body: Optional[Any] = None) -> tuple[int, str]:
    remaining = _remaining_request_seconds()

    async def request() -> tuple[int, str]:
        # A client is scoped to this request because callers may use separate asyncio.run() loops.
        # The explicit SSLContext preserves the operating system trust store used by urllib.
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=remaining,
            verify=ssl.create_default_context(),
        ) as client:
            response = await client.request(method, url, headers=headers, json=json_body)
            return response.status_code, response.text

    try:
        if remaining is None:
            return await request()
        # HTTPX timeouts bound inactivity per operation. wait_for additionally bounds the complete
        # request and body read when a peer sends a byte often enough to evade a read timeout.
        # OS DNS resolution can outlive cancellation and delay asyncio.run() executor shutdown;
        # this deadline governs approval acceptance and cancellable HTTP I/O, not process shutdown.
        return await asyncio.wait_for(request(), timeout=remaining)
    except asyncio.TimeoutError as e:
        raise GatewayUnreachable("Connection failed: approval deadline elapsed") from e
    except httpx.RequestError as e:
        raise GatewayUnreachable(f"Connection failed: {e}") from e

class IntygaClient:
    def __init__(
        self,
        gateway_url: str,
        token: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        target: Optional[str] = None,
        allow_stored_credentials: bool = False,
    ):
        """
        `target` names the relying party / execution environment approvals raised through this client
        are bound to (DIV §3 Invariant 5, Target Isolation). Supply it: when it is absent the gateway
        falls back to the literal "global", and an approval bound to "global" verifies at every other
        relying party that also uses "global" — the cross-service replay this invariant exists to
        prevent. It can be passed per call instead, but not omitted at both.

        `allow_stored_credentials` gates reading `~/.intyga/credentials.json`. It defaults to False
        and is intended for CLI tools, matching @intyga/sdk. Reading it unconditionally meant a
        service constructed with no credentials — which should raise — silently assumed whatever
        principal a human's `intyga login` had left in that account's home directory.
        """
        self._gateway_url = gateway_url.rstrip("/")
        self._token = token
        self._client_id = client_id
        self._client_secret = client_secret
        self._target = target
        self._allow_stored_credentials = allow_stored_credentials
        # The cache: the token, where it came from ("exchange" — re-exchangeable from
        # client_id/client_secret — or "stored", an `intyga login` credential nothing here can
        # renew), and when it expires on time.monotonic() (None = unknown; cache until a 401).
        self._cached_token: Optional[str] = None
        self._cached_source: Optional[str] = None
        self._cached_expires_at: Optional[float] = None
        self._cached_margin: float = 0.0

    def _resolve_target(self, target: Optional[str]) -> str:
        resolved = target if target is not None else self._target
        if not resolved or not resolved.strip():
            raise ValueError(
                "target is required (DIV Target Isolation): name the relying party / execution "
                "environment this approval is bound to, on the call or on IntygaClient(...)"
            )
        return resolved.strip()

    def _invalidate_token(self) -> None:
        """Drop the cached token so the next `token()` re-resolves it (re-exchange or re-read)."""
        self._cached_token = None
        self._cached_source = None
        self._cached_expires_at = None
        self._cached_margin = 0.0

    def _cache_is_fresh(self) -> bool:
        if self._cached_expires_at is None:
            return True
        return _monotonic() < self._cached_expires_at - self._cached_margin

    async def token(self) -> str:
        """Resolve a bearer token: the provided one, a still-fresh cached one, a stored `intyga login`
        credential, or a fresh client-credentials exchange.

        An exchanged token is cached until shortly before the `expires_in` the gateway advertised
        (see `_REFRESH_MARGIN_MAX_SECONDS`) and then exchanged again, so a long-lived service or a
        long `require_approval` poll never dies at token expiry. A stored credential has no secret
        to re-exchange with: its JWT `exp` is decoded (unverified — a hint for the error message
        only) and an expired one raises `GatewayRefused(401)` naming `intyga login` as the fix.
        """
        if self._token:
            return self._token
        cached = self._cached_token
        if cached is not None and self._cache_is_fresh():
            return cached
        self._invalidate_token()
        if self._allow_stored_credentials:
            stored = _load_stored_token(self._gateway_url)
            if stored:
                exp = _decode_jwt_exp(stored)
                if exp is not None:
                    remaining = exp - time.time()
                    if remaining <= 0:
                        raise GatewayRefused(401, _STORED_CREDENTIAL_EXPIRED)
                    # Wall-clock `exp` mapped onto the monotonic clock; margin 0 because there is
                    # nothing to renew it with, so it is served for its whole remaining life.
                    self._cached_expires_at = _monotonic() + remaining
                self._cached_token = stored
                self._cached_source = "stored"
                return stored
        return await self._exchange()

    async def _exchange(self) -> str:
        """The client-credentials exchange itself, bypassing the stored-credential lookup.

        The 401 retry in `_request_authed` calls this directly: going back through `token()` would
        consult `~/.intyga/credentials.json` first, so a process configured with BOTH a stored
        `intyga login` token and client credentials could retry an agent call as the human — a
        different principal, a different ceremony shape, and a different requester on the witness leaf.
        """
        if not self._client_id or not self._client_secret:
            raise ValueError("provide `token`, or `client_id` + `client_secret`, or run `intyga login` first")

        basic = base64.b64encode(f"{self._client_id}:{self._client_secret}".encode("utf-8")).decode("utf-8")
        status, body = await _async_request(
            f"{self._gateway_url}/oauth/token",
            method="POST",
            headers={"authorization": f"Basic {basic}"}
        )
        if status < 200 or status >= 300:
            raise GatewayRefused(status, f"token exchange failed: {status} {body}")

        data = json.loads(body)
        access_token = data["access_token"]
        expires_in = _numeric_expires_in(data.get("expires_in"))
        self._cached_token = access_token
        self._cached_source = "exchange"
        if expires_in is not None:
            self._cached_expires_at = _monotonic() + expires_in
            self._cached_margin = _refresh_margin(expires_in)
        return access_token

    async def _request_authed(
        self,
        op: str,
        url: str,
        method: str = "GET",
        json_body: Optional[Any] = None,
        _retried: bool = False,
    ) -> Dict[str, Any]:
        """One bearer-authenticated request, parsed as JSON; every non-2xx raises GatewayRefused.

        A 401 against a token this client exchanged itself — not an explicit `token`, not a stored
        credential — clears the cache and retries exactly once with a fresh client-credentials
        exchange (never a stored credential — see `_exchange`). The margin in
        `token()` handles ordinary expiry; this covers clock skew and a gateway-side TTL change. An
        explicit token has nothing to re-exchange, so its 401 is the verdict it always was, and a
        stored `intyga login` credential gets the authored "log in again" error instead.
        """
        token_str = await (self._exchange() if _retried else self.token())
        headers = {"authorization": f"Bearer {token_str}"}
        if json_body is not None:
            headers["content-type"] = "application/json"
        status, body = await _async_request(url, method=method, headers=headers, json_body=json_body)
        if status == 401 and not self._token:
            if self._cached_source == "exchange" and not _retried:
                self._invalidate_token()
                return await self._request_authed(op, url, method=method, json_body=json_body, _retried=True)
            if self._cached_source == "stored":
                self._invalidate_token()
                raise GatewayRefused(401, f"{op} failed: {_STORED_CREDENTIAL_REJECTED}")
        if status < 200 or status >= 300:
            raise GatewayRefused(status, f"{op} failed: {status} {body}")
        return json.loads(body)

    async def authorize(
        self,
        action_description: str,
        action_type: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        target: Optional[str] = None,
        agent_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Request action authorization (creates a challenge)."""
        payload = {
            "target": self._resolve_target(target),
            "actionDescription": action_description,
            "params": params if params is not None else {},
        }
        if action_type is not None:
            payload["actionType"] = action_type
        if timeout is not None:
            payload["timeout"] = timeout
        if agent_context is not None:
            payload["agentContext"] = agent_context

        return await self._request_authed(
            "authorize", f"{self._gateway_url}/authorize", method="POST", json_body=payload
        )

    async def consume(
        self,
        nonce: str,
        action_type: str,
        params: Optional[Dict[str, Any]] = None,
        target: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Confirm that the approved signature matches the exact instruction and marks it single-use.

        `target` is REQUIRED by the gateway's authorizationConsume schema. Omitting it was a 400 on
        every call, so single-use redemption was unreachable from this SDK: the challenge stayed
        APPROVED rather than CONSUMED and remained replayable for the rest of its TTL.
        """
        payload = {
            "nonce": nonce,
            "target": self._resolve_target(target),
            "actionType": action_type,
            "params": params if params is not None else {}
        }
        return await self._request_authed(
            "consume", f"{self._gateway_url}/authorize/verify", method="POST", json_body=payload
        )

    async def status(self, nonce: str) -> Dict[str, Any]:
        """Poll a challenge's current status (non-blocking)."""
        return await self._request_authed(
            "status", f"{self._gateway_url}/authorize/{urllib.parse.quote(nonce)}", method="GET"
        )

    async def require_approval(
        self,
        action_description: str,
        action_type: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        timeout_ms: Optional[int] = None,
        interval_ms: Optional[int] = None,
        target: Optional[str] = None,
        agent_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a challenge and block until approved, denied, or expired."""
        resolved_timeout_ms = (
            timeout_ms
            if timeout_ms is not None
            else timeout * 1000 if timeout is not None
            else _DEFAULT_APPROVAL_TIMEOUT_MS
        )
        if (
            isinstance(resolved_timeout_ms, bool)
            or not isinstance(resolved_timeout_ms, (int, float))
            or not math.isfinite(resolved_timeout_ms)
            or resolved_timeout_ms <= 0
        ):
            raise ValueError("timeout must be a finite number greater than zero")
        backend_timeout_sec = math.ceil(resolved_timeout_ms / 1000)
        deadline = _monotonic() + (resolved_timeout_ms / 1000)
        resolved_interval_ms = interval_ms if interval_ms is not None else 2_000
        if (
            isinstance(resolved_interval_ms, bool)
            or not isinstance(resolved_interval_ms, (int, float))
            or not math.isfinite(resolved_interval_ms)
            or resolved_interval_ms <= 0
        ):
            raise ValueError("interval_ms must be a finite number greater than zero")
        interval_sec = resolved_interval_ms / 1000
        deadline_token = _request_deadline.set(deadline)
        try:
            # `target` must be forwarded, not dropped. The Go and Rust ports rebuilt their options
            # struct here field-by-field and lost it on exactly this path — the one most callers use.
            auth_res = await self.authorize(
                action_description=action_description,
                action_type=action_type,
                params=params,
                timeout=backend_timeout_sec,
                target=target,
                agent_context=agent_context,
            )
            nonce = auth_res["nonce"]

            # The nonce is merged into every return, terminal and expired alike — it is the challenge
            # this result belongs to, and without it the one-shot helper's caller cannot pass
            # `expected["nonce"]` to verify_approval_receipt or record redemption for their own
            # single-use check. Matches @intyga/sdk, sdk-go and sdk-rust, which all set it.
            while True:
                if _monotonic() >= deadline:
                    return {"status": "EXPIRED", "nonce": nonce}
                r = await self.status(nonce)
                # The response is useful only if it arrived inside this relying party's wait
                # window. Recheck after the await before accepting even an APPROVED status.
                if _monotonic() >= deadline:
                    return {"status": "EXPIRED", "nonce": nonce}
                if r.get("status") != "PENDING":
                    return {**r, "nonce": nonce}
                remaining = deadline - _monotonic()
                if remaining <= 0:
                    return {"status": "EXPIRED", "nonce": nonce}
                await asyncio.sleep(min(interval_sec, remaining))
        finally:
            _request_deadline.reset(deadline_token)

    async def verify(self, document_hash: str) -> Dict[str, Any]:
        """Lookup a signed document witness by hash."""
        status, body = await _async_request(
            f"{self._gateway_url}/verify/{urllib.parse.quote(document_hash)}",
            method="GET"
        )
        if status < 200 or status >= 300:
            raise GatewayRefused(status, f"verify failed: {status} {body}")
        return json.loads(body)
