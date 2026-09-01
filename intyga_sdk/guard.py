"""Gate any Python callable behind a signed human approval.

This is the agent-framework integration surface. LangChain, CrewAI and every similar framework
reduce a "tool" to a Python callable — so one wrapper at the callable level covers all of them,
instead of one adapter per framework that rots with each framework release. See the README's
"Gate a LangChain or CrewAI tool" section for the per-framework recipes.

Design constraints, stated because they are load-bearing:

- The parameters shown to the approver AND bound into the signed payload are the call's KEYWORD
  arguments, verbatim. Positional arguments are refused outright — a signed approval binds named
  parameters, and a bare positional value would be displayed and signed as nothing.
- The wrapped function runs with exactly the kwargs that were approved. There is no window to
  mutate them between approval and execution inside this wrapper; anything the function itself
  does afterwards is, as always, its own responsibility.
- Refusal is an exception (`ApprovalRefused`), never a return value, so a framework cannot
  silently treat "the human said no" as a tool result.
- Without `approvers` the guard gates on the gateway's `status` STRING and nothing else — it is
  transport trust, not cryptographic proof. DIV §5 requires the Relying Party to verify the
  signature locally against keys IT resolved, immediately before the irreversible action; only the
  `approvers` path does that. The unverified path is kept for backward compatibility and warns at
  decoration time rather than staying silent about what it does not check.
"""

import asyncio
import functools
import inspect
import warnings
from typing import Any, Callable, Dict, Optional

from .client import IntygaClient
from .crypto import verify_approval_receipt
from .errors import ApprovalRefused


def require_human_approval(
    client: IntygaClient,
    *,
    action_type: Optional[str] = None,
    description: Optional[str] = None,
    target: Optional[str] = None,
    timeout_ms: Optional[int] = None,
    approvers: Optional[Dict[str, Any]] = None,
    expected_origin: Optional[str] = None,
    expected_rp_id: Optional[str] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory: the wrapped callable executes only after a human approves it.

    `action_type` defaults to the wrapped function's name — the name a policy rule matches on.
    `target` follows the client's normal resolution (per-call here, or set on the client);
    the gateway-side requirement that a target exists is unchanged.

    `approvers` is the trust anchor YOU resolved — `{"publicKeys": [...]}` or the DID/identity form
    — and supplying it is what turns this decorator from a transport-trust convenience into a DIV
    §5 relying party. With it, the guard re-derives the canonical payload from the target, action
    type and kwargs it is about to execute, verifies the receipt's signatures against those keys,
    and redeems the nonce, all before the wrapped function runs. A result carrying no `receipt` is
    then a refusal: an approval that cannot be proved is not an approval.

    `expected_origin` / `expected_rp_id` are forwarded to the receipt verifier and are REQUIRED for
    a WEBAUTHN (passkey) witness to be countable (DIV §4.4.5, fail-closed when unset).

    Omitting `approvers` keeps the pre-existing behavior — the gateway's `status` string is trusted
    — and warns, because the caller is then relying on the transport rather than on a signature.

    Works on both sync and async callables. A SYNC callable can only be guarded outside a running
    event loop (the guard must block on the approval; inside a loop that would deadlock, so it
    raises with instructions to make the tool async instead).
    """

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        resolved_action = action_type or fn.__name__

        if approvers is None:
            warnings.warn(
                f"'{resolved_action}' is guarded without `approvers`: the gateway's status string is "
                "the only thing gating execution, and the signed receipt is never checked. Pass "
                "approvers={'publicKeys': [...]} (or the DID form) so the signature is verified "
                "locally before the call runs (DIV §5).",
                UserWarning,
                stacklevel=2,
            )

        def refuse_positional(args: tuple) -> None:
            if args:
                raise TypeError(
                    f"'{resolved_action}' is approval-gated: pass parameters as keyword arguments "
                    "so the approver sees and signs each one by name (LangChain StructuredTool and "
                    "CrewAI @tool both call with keywords)"
                )

        async def approve(kwargs: Dict[str, Any]) -> None:
            result = await client.require_approval(
                description or f"Execute {resolved_action}",
                action_type=resolved_action,
                params=kwargs,
                target=target,
                timeout_ms=timeout_ms,
            )
            status = result.get("status", "UNKNOWN")
            if status != "APPROVED":
                raise ApprovalRefused(status, f"'{resolved_action}' was not approved: {status}")
            if approvers is None:
                return

            receipt = result.get("receipt")
            if not isinstance(receipt, dict):
                raise ApprovalRefused(
                    "UNVERIFIED",
                    f"'{resolved_action}' was reported APPROVED but the response carries no receipt "
                    "to verify — refusing, because an approval that cannot be proved is not one",
                )
            # The target comes from THIS relying party's own configuration — the same resolution the
            # challenge was raised under — never from the receipt, which would have it vouch for its
            # own scope (DIV Target Isolation).
            check = verify_approval_receipt(
                receipt,
                {
                    "target": client._resolve_target(target),
                    "actionType": resolved_action,
                    "params": kwargs,
                    "nonce": result.get("nonce"),
                    "approvers": approvers,
                },
                expected_origin=expected_origin,
                expected_rp_id=expected_rp_id,
            )
            if not check.get("ok"):
                raise ApprovalRefused(
                    "UNVERIFIED",
                    f"'{resolved_action}' has an approval that does not verify: {check.get('reason')}",
                )
            # Redeem AFTER the local check, so a gateway that cannot be believed about the signature
            # is not believed about single-use either. Without this the challenge stays APPROVED and
            # replayable for the rest of its TTL.
            await client.consume(
                nonce=result.get("nonce"),
                action_type=resolved_action,
                params=kwargs,
                target=target,
            )

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                refuse_positional(args)
                await approve(kwargs)
                return await fn(**kwargs)

            return async_wrapper

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            refuse_positional(args)
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                pass  # no running loop — the normal sync case
            else:
                raise RuntimeError(
                    f"'{resolved_action}' is a sync function guarded inside a running event loop — "
                    "the guard would deadlock blocking on the approval. Make the tool function "
                    "async; the guard awaits it natively."
                )
            asyncio.run(approve(kwargs))
            return fn(**kwargs)

        return sync_wrapper

    return decorate
