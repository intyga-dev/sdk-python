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
"""

import asyncio
import functools
import inspect
from typing import Any, Callable, Dict, Optional

from .client import IntygaClient
from .errors import ApprovalRefused


def require_human_approval(
    client: IntygaClient,
    *,
    action_type: Optional[str] = None,
    description: Optional[str] = None,
    target: Optional[str] = None,
    timeout_ms: Optional[int] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory: the wrapped callable executes only after a human approves it.

    `action_type` defaults to the wrapped function's name — the name a policy rule matches on.
    `target` follows the client's normal resolution (per-call here, or set on the client);
    the gateway-side requirement that a target exists is unchanged.

    Works on both sync and async callables. A SYNC callable can only be guarded outside a running
    event loop (the guard must block on the approval; inside a loop that would deadlock, so it
    raises with instructions to make the tool async instead).
    """

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        resolved_action = action_type or fn.__name__

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
