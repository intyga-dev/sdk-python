import asyncio
import base64
import json
import math
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

from .errors import GatewayRefused, GatewayUnreachable

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

def _sync_request(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, json_body: Optional[Any] = None) -> tuple[int, str]:
    headers = headers or {}
    req = urllib.request.Request(url, method=method, headers=headers)
    if json_body is not None:
        req.data = json.dumps(json_body).encode("utf-8")
        req.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8")
        except Exception:
            body = ""
        return e.code, body
    except urllib.error.URLError as e:
        raise GatewayUnreachable(f"Connection failed: {e.reason}")

async def _async_request(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, json_body: Optional[Any] = None) -> tuple[int, str]:
    return await asyncio.to_thread(_sync_request, url, method, headers, json_body)

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
        self._cached_token = None

    def _resolve_target(self, target: Optional[str]) -> str:
        resolved = target if target is not None else self._target
        if not resolved or not resolved.strip():
            raise ValueError(
                "target is required (DIV Target Isolation): name the relying party / execution "
                "environment this approval is bound to, on the call or on IntygaClient(...)"
            )
        return resolved.strip()

    async def token(self) -> str:
        """Resolve a bearer token: the provided one, a cached exchange, or a fresh client-credentials exchange."""
        if self._token:
            return self._token
        if self._cached_token:
            return self._cached_token
        if self._allow_stored_credentials:
            stored = _load_stored_token(self._gateway_url)
            if stored:
                self._cached_token = stored
                return stored
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
        self._cached_token = data["access_token"]
        return self._cached_token

    async def authorize(
        self,
        action_description: str,
        action_type: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        target: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Request action authorization (creates a challenge)."""
        token_str = await self.token()
        payload = {
            "target": self._resolve_target(target),
            "actionDescription": action_description,
            "actionType": action_type,
            "params": params if params is not None else {},
        }
        if timeout is not None:
            payload["timeout"] = timeout

        status, body = await _async_request(
            f"{self._gateway_url}/authorize",
            method="POST",
            headers={
                "authorization": f"Bearer {token_str}",
                "content-type": "application/json"
            },
            json_body=payload
        )
        if status < 200 or status >= 300:
            raise GatewayRefused(status, f"authorize failed: {status} {body}")
        return json.loads(body)

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
        token_str = await self.token()
        payload = {
            "nonce": nonce,
            "target": self._resolve_target(target),
            "actionType": action_type,
            "params": params if params is not None else {}
        }
        status, body = await _async_request(
            f"{self._gateway_url}/authorize/verify",
            method="POST",
            headers={
                "authorization": f"Bearer {token_str}",
                "content-type": "application/json"
            },
            json_body=payload
        )
        if status < 200 or status >= 300:
            raise GatewayRefused(status, f"consume failed: {status} {body}")
        return json.loads(body)

    async def status(self, nonce: str) -> Dict[str, Any]:
        """Poll a challenge's current status (non-blocking)."""
        token_str = await self.token()
        status, body = await _async_request(
            f"{self._gateway_url}/authorize/{urllib.parse.quote(nonce)}",
            method="GET",
            headers={"authorization": f"Bearer {token_str}"}
        )
        if status < 200 or status >= 300:
            raise GatewayRefused(status, f"status failed: {status} {body}")
        return json.loads(body)

    async def require_approval(
        self,
        action_description: str,
        action_type: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        timeout_ms: Optional[int] = None,
        interval_ms: Optional[int] = None,
        target: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a challenge and block until approved, denied, or expired."""
        backend_timeout_sec = math.ceil(timeout_ms / 1000) if timeout_ms is not None else timeout

        # `target` must be forwarded, not dropped. The Go and Rust ports rebuilt their options
        # struct here field-by-field and lost it on exactly this path — the one most callers use.
        auth_res = await self.authorize(
            action_description=action_description,
            action_type=action_type,
            params=params,
            timeout=backend_timeout_sec,
            target=target,
        )
        nonce = auth_res["nonce"]

        deadline = (time.time() * 1000) + (timeout_ms if timeout_ms is not None else 120000)
        interval_sec = (interval_ms / 1000) if interval_ms is not None else 2.0

        # The nonce is merged into every return, terminal and expired alike — it is the challenge
        # this result belongs to, and without it the one-shot helper's caller cannot pass
        # `expected["nonce"]` to verify_approval_receipt or record redemption for their own
        # single-use check. Matches @intyga/sdk, sdk-go and sdk-rust, which all set it.
        while True:
            r = await self.status(nonce)
            if r.get("status") != "PENDING":
                return {**r, "nonce": nonce}
            if (time.time() * 1000) > deadline:
                return {"status": "EXPIRED", "nonce": nonce}
            await asyncio.sleep(interval_sec)

    async def verify(self, document_hash: str) -> Dict[str, Any]:
        """Lookup a signed document witness by hash."""
        status, body = await _async_request(
            f"{self._gateway_url}/verify/{urllib.parse.quote(document_hash)}",
            method="GET"
        )
        if status < 200 or status >= 300:
            raise GatewayRefused(status, f"verify failed: {status} {body}")
        return json.loads(body)
