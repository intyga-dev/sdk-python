# intyga-sdk — Universal Governance for Automated Operations (Python)

One SDK for every Intyga use case, implemented in Python.

## Installation

```bash
pip install intyga-sdk
```

## Require a human approval before a high-risk action

`target` is required — it names THIS execution environment, so the approval cannot be replayed
against a different service (DIV Target Isolation). Issue the challenge with `authorize()` so you
own the `nonce`: verification needs it, and it is what lets you enforce single-use yourself.

```python
import asyncio
import os
from intyga_sdk import IntygaClient, verify_approval_receipt

TARGET = "prod-db-cluster-01"                                   # THIS relying party — required
APPROVERS = {"publicKeys": os.environ["INTYGA_APPROVER_KEYS"].split(",")}

intyga = IntygaClient(
    gateway_url=os.environ["INTYGA_GATEWAY_URL"],
    client_id=os.environ["INTYGA_CLIENT_ID"],
    client_secret=os.environ["INTYGA_CLIENT_SECRET"],
    target=TARGET,
)

async def delete_production_database(database: str):
    action_type, params = "wipe_production", {"database": database}

    # Issue the challenge yourself so you own the nonce — verification needs it.
    started = await intyga.authorize(
        f"Delete production database {database}",
        action_type=action_type,
        params=params,
    )
    nonce = started["nonce"]

    while True:
        approval = await intyga.status(nonce)
        if approval["status"] != "PENDING":
            break
        await asyncio.sleep(2)
    if approval["status"] != "APPROVED":
        raise Exception(f"Not authorized: {approval['status']}")

    # Prove it in YOUR code: re-derive the payload from the params you are about to execute.
    # If they differ by one byte from what the human saw and signed, this fails. `approvers`
    # is the key set YOU trust, from your own key management — never read from the receipt.
    check = verify_approval_receipt(approval["receipt"], {
        "target": TARGET,
        "actionType": action_type,
        "params": params,
        "nonce": nonce,
        "approvers": APPROVERS,
    })
    if not check["ok"]:
        raise Exception(f"Refusing to proceed: {check['reason']}")
    await really_drop_the_database(database)
```

## Gate a LangChain or CrewAI tool

Agent frameworks reduce a "tool" to a Python callable, so one decorator covers all of them:
`require_human_approval` wraps any sync or async callable so it executes only after a signed human
approval. The approver sees — and signs — the call's keyword arguments by name (positional
arguments are refused for exactly that reason), and a refusal raises `ApprovalRefused` rather than
returning a value, so a framework cannot mistake "the human said no" for a tool result.

```python
import os
from intyga_sdk import IntygaClient, require_human_approval

intyga = IntygaClient(
    gateway_url=os.environ["INTYGA_GATEWAY_URL"],
    client_id=os.environ["INTYGA_CLIENT_ID"],
    client_secret=os.environ["INTYGA_CLIENT_SECRET"],
    target="agent-payments-prod",
)

@require_human_approval(intyga, description="Send a wire transfer")
def wire_transfer(*, to: str, amount: int, currency: str) -> str:
    """Send a wire transfer to a named counterparty."""
    return execute_transfer(to, amount, currency)
```

**LangChain** — hand the guarded callable to a structured tool as usual:

```python
from langchain_core.tools import StructuredTool

transfer_tool = StructuredTool.from_function(wire_transfer)
```

**CrewAI** — stack the decorators; the guard sits under the framework's:

```python
from crewai.tools import tool

@tool("wire_transfer")
@require_human_approval(intyga, action_type="wire_transfer")
def wire_transfer(*, to: str, amount: int) -> str:
    """Send a wire transfer."""
    return execute_transfer(to, amount, "USD")
```

`action_type` defaults to the function name — the name a gateway `ApprovalRule` or local policy
matches on. A sync tool can only be guarded outside a running event loop (the guard must block on
the human); inside async frameworks, make the tool function `async` and the guard awaits natively.

## Typed errors

Everything the SDK raises deliberately subclasses `IntygaError`:

- `GatewayRefused` (with `.status`) — the gateway **answered** and the answer was no: 403 policy
  refusal, 402 Protected Ops exhausted, 401/429. A verdict, not an outage.
- `GatewayUnreachable` — transport failure: the gateway could not be asked at all.
- `ApprovalRefused` (with `.status`: `DENIED`, `EXPIRED`, …) — a guarded call was not approved.

The refusal/outage split is load-bearing (DIV §5a): a policy denial must never be handled as
unreachability.

## Verifying an approval receipt

`intyga_sdk.crypto.verify_approval_receipt` checks a receipt against keys **you** resolved — never the
one embedded in the receipt, which would prove only that the receipt is self-consistent.

> **Quorum caveat.** The trust anchor accepts either a flat public-key allowlist or a DID/identity
> form. In key-list mode the identity IS the key, so an M-of-N quorum counts credentials, not people:
> one approver whose two registered credentials are both listed satisfies a 2-of-N alone. For
> `requiredApprovals` > 1 use the DID/identity form, which counts distinct approvers (DIV §4.4.6).
> Delegations name approver identities and are refused outright in key-list mode.

## DEWP conformance

`intyga_sdk.ledger` implements the **DEWP Core primitives** ([`docs/DEWP.md`](../../docs/DEWP.md) §9.1) —
domain-separated hashing, two-tier Merkle construction, inclusion proof verification, the
`trust.intyga.audit.v1` canonical preimage, the `0x03` anchor digest — plus single-bundle verification
with the §7.1 property model (`verify_bundle`). Parity with the TypeScript reference is locked by the
shared golden vectors in `packages/mcp-schemas/vectors/ledger-vectors.json`.

Three limits are deliberate and reported honestly rather than silently:

- **`signature_verified` is always `False`.** Re-verifying the embedded DIV ES256 signature would pull
  a cryptography dependency into a module that otherwise needs only `hashlib`. A signed event therefore
  reports `CONTENT_VERIFIED` here where the TypeScript verifier would report `SIGNATURE_VERIFIED` — the
  commitment result is identical; only the signature claim is withheld.
- **Anchor quorum verification (§5.3) is not implemented,** so **`anchor_verified` is always `False`
  and `FULLY_VERIFIED` is not reachable from this port.** §3.7 makes that property conditional on a
  quorum of distinct trusted issuers signing the same `dailyRoot`; with no quorum check there is
  nothing to base it on. `verify_anchor_signature` exists, but it is exactly what its name says — a
  standalone single-anchor ES256 check over the raw 32-byte digest (§5.2, pinned by the shared
  `signedAnchor` vectors), not quorum and not bundle-level anchor verification, and it is
  deliberately not wired into `verify_bundle`. A bundle whose commitment and content both verify
  against an independently supplied root reports `CONTENT_VERIFIED` with `ok: True` and a note
  explaining the gap. (Until Jul 2026 this port set `anchor_verified` from the mere presence of a
  trusted root and reported `FULLY_VERIFIED` — a label that asserted more than had been checked.)
- **The §5.4 checkpoint continuity chain (`0x04` domain tag) is not implemented.** It is TS-only:
  DEWP §9.1 places it outside the Core primitives this port targets. Use `@intyga/verify` to check
  a checkpoint chain.

`verify_bundle` also refuses any `kind` other than `dewp.audit.inclusion-proof` (§6.5), and declines to
attempt leaf binding for an Application Profile other than `trust.intyga.audit.v1` (§4.5) rather than
reporting a mismatch that would read as tampering.

For the rest of the surface — signed multi-anchor quorum, evidence bundles with full anchor
evaluation and the four-property model at strength — use the TypeScript verifier
(`@intyga/verify`). Note that no implementation, the TypeScript one included, currently claims the
§9.2 **Extended Profile**: the profile also requires NDJSON evidence streaming (§6.4), which is
specified but not yet implemented anywhere.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
