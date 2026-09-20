# intyga-sdk — Universal Governance for Automated Operations (Python)

One SDK for every Intyga use case, implemented in Python.

## Installation

> Status: **not yet published** to PyPI. Until then, install from a checkout of this directory:
> `pip install -e .`

```bash
pip install intyga-sdk
```

## Require a human approval before a high-risk action

`target` is required — it names THIS execution environment, so the approval cannot be replayed
against a different service (DIV Target Isolation). Issue the challenge with `authorize()` so you
own the `nonce`: verification needs it, and it is what lets you enforce single-use yourself.
The example below is for a human or `SERVICE` key. With an `AI_AGENT` key, pass
`agent_context` to `authorize()` and an independently retained `agentContext` to the verifier.
The executing PEP must recalculate the digest from its live model, tools and prompt and maintain
an atomic session head and budget across sessions (DIV §4.3.6).

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
    },
        # REQUIRED for passkey receipts: pin the assertion to YOUR approval console
        # (the deployment's WEBAUTHN_ORIGIN / WEBAUTHN_RP_ID), or verification fails closed.
        expected_origin=os.environ["INTYGA_WEBAUTHN_ORIGIN"],
        expected_rp_id=os.environ["INTYGA_WEBAUTHN_RP_ID"],
    )
    if not check["ok"]:
        raise Exception(f"Refusing to proceed: {check['reason']}")
    # Redeem the exact verified instruction before executing so this nonce is single-use.
    await intyga.consume(nonce, action_type, params=params)
    await really_drop_the_database(database)
```

The client exchanges `client_id` / `client_secret` for a bearer token on first use and re-exchanges
it automatically shortly before the `expires_in` the gateway advertised (and once more on an
unexpected 401), so a long-lived service or a long poll never dies at token expiry. A stored
`intyga login` credential cannot be refreshed: when it expires the SDK raises `GatewayRefused`
telling you to run `intyga login` again.

`require_approval(timeout=600)` uses 600 seconds for both the gateway TTL and local approval wait;
`timeout_ms`, when supplied, takes precedence. A monotonic deadline prevents accepting late results
and cancels HTTP I/O, including a slowly streaming response. Python's OS hostname resolver can
outlive cancellation and delay `asyncio.run()` shutdown if DNS stalls; the deadline is not a hard
bound on process shutdown. Literal-IP loopback tests cover active HTTP connection cancellation.
HTTP transport uses HTTPX's cancellable async client with the operating system TLS trust store.
Authenticated redirects are refused, and approval polling applies one monotonic total deadline to
token exchange, challenge creation, status responses and their complete response bodies.

## Gate a LangChain or CrewAI tool

Agent frameworks reduce a "tool" to a Python callable, so one decorator covers all of them:
`require_human_approval` wraps any sync or async callable so it executes only after a human
approval. The approver sees — and signs — the call's keyword arguments by name (positional
arguments are refused for exactly that reason), and a refusal raises `ApprovalRefused` rather than
returning a value, so a framework cannot mistake "the human said no" for a tool result.

**Pass `approvers`.** It is what makes the decorator a DIV §5 relying party rather than a
transport-trust convenience — the same check the manual example above performs, run for you
immediately before the call:

```python
import os
from intyga_sdk import IntygaClient, require_human_approval

intyga = IntygaClient(
    gateway_url=os.environ["INTYGA_GATEWAY_URL"],
    client_id=os.environ["INTYGA_CLIENT_ID"],
    client_secret=os.environ["INTYGA_CLIENT_SECRET"],
    target="agent-payments-prod",
)
APPROVERS = {"publicKeys": os.environ["INTYGA_APPROVER_KEYS"].split(",")}

@require_human_approval(intyga, description="Send a wire transfer", approvers=APPROVERS)
def wire_transfer(*, to: str, amount: int, currency: str) -> str:
    """Send a wire transfer to a named counterparty."""
    return execute_transfer(to, amount, currency)
```

With `approvers`, the guard re-derives the canonical payload from the target it raised the
challenge under and the kwargs it is about to execute, verifies the receipt's signatures against
**your** keys, redeems the nonce (`consume`) so the approval is single-use, and only then calls the
function. A result carrying no `receipt` is a refusal. Pass `expected_origin` and `expected_rp_id`
too — a WEBAUTHN witness is not countable without them (DIV §4.4.5, fail-closed when unset).
The guard first validates and deep-copies the keyword arguments as canonical JSON; approval,
verification, consumption and execution all use that detached snapshot, so another task cannot
replace a nested value while an HTTP request is pending. The function therefore receives JSON
types — a tuple arrives as a list, and `1.0` as `1` — and an argument with no portable JSON form
(NaN, `-0.0`, integers outside the portable range) is refused before any challenge is created.

**Without `approvers` nothing is verified.** The guard then gates on the gateway's `status` string
alone: it never reads the receipt, checks no signature, and does not redeem the nonce. That is
trust in the transport, not cryptographic proof, and it is what DIV Invariants 2 and 3 exist to
remove — so the decorator emits a `UserWarning` at decoration time. The path is kept only so
existing callers keep working.

**LangChain** — hand the guarded callable to a structured tool as usual:

```python
from langchain_core.tools import StructuredTool

transfer_tool = StructuredTool.from_function(wire_transfer)
```

**CrewAI** — stack the decorators; the guard sits under the framework's:

```python
from crewai.tools import tool

@tool("wire_transfer")
@require_human_approval(intyga, action_type="wire_transfer", approvers=APPROVERS)
def wire_transfer(*, to: str, amount: int) -> str:
    """Send a wire transfer."""
    return execute_transfer(to, amount, "USD")
```

`action_type` defaults to the function name — the name a gateway `ApprovalRule` or local policy
matches on. A sync tool can only be guarded outside a running event loop (the guard must block on
the human); inside async frameworks, make the tool function `async` and the guard awaits natively.

## Typed errors

Everything the SDK raises deliberately subclasses `IntygaError`:

- `GatewayRefused` (with `.status`) — the gateway **answered** and the answer was no: for example a
  403 policy refusal or 401/429. A verdict, not an outage. (Usage no longer produces 402.)
- `GatewayUnreachable` — transport failure: the gateway could not be asked at all.
- `ApprovalRefused` (with `.status`: `DENIED`, `EXPIRED`, …) — a guarded call was not approved.

The refusal/outage split is load-bearing (DIV §5a): a policy denial must never be handled as
unreachability.

## Verifying an approval receipt

`intyga_sdk.crypto.verify_approval_receipt` checks a receipt against keys **you** resolved — never the
one embedded in the receipt, which would prove only that the receipt is self-consistent.

`expected` must name `target`, `actionType`, `params`, `nonce` and `approvers`. All five are
required and an omitted key is a refusal, not a default: the first three are DIV §4.4.1
security-binding fields that must come from your own runtime, and rebuilding the payload with `""`
or `{}` because a key was misspelled would bind the receipt to nothing.

For **passkey receipts** — the normal flow — also pass `expected_origin` and `expected_rp_id` (the
origin and RP ID of the approval console the human signs in, i.e. your deployment's
`WEBAUTHN_ORIGIN` / `WEBAUTHN_RP_ID`). The verifier fails closed on a WebAuthn witness without
them: an assertion harvested at any other relying party would otherwise verify. Raw-key (ES256)
receipts carry no assertion, so the two values are simply unused there.

> **Quorum caveat.** The trust anchor accepts either a flat public-key allowlist or a DID/identity
> form. In key-list mode the identity IS the key, so an M-of-N quorum counts credentials, not people:
> one approver whose two registered credentials are both listed satisfies a 2-of-N alone. A signed
> `requesterCannotApprove` rule requires DID/identity trust; key-list mode is refused.
> For `requiredApprovals` > 1, use the DID/identity form, which counts distinct approvers (DIV §4.4.6).
> Delegations name approver identities and are refused outright in key-list mode.

`WEBAUTHN` (passkey) witnesses are verified in full per DIV §4.4.5 — origin and RP ID pinning
(fail-closed when unset), user-presence/user-verification flags, challenge binding to the canonical
payload, and the ES256 signature over `authenticatorData ‖ SHA-256(clientDataJSON)` — pinned by the
shared `webauthn-vector.json` golden vector (`tests/test_webauthn.py`). Pass `expected_origin` and
`expected_rp_id` to enable it.

## Receipt and audit verification

`verify_platform_receipt` and `verify_agent_authority` are exported alongside
`verify_approval_receipt` and `verify_delegation`. Ledger APIs live in `intyga_sdk.ledger`:
`verify_bundle`, `verify_evidence_bundle`, `verify_roots_chain`, `verify_anchor_quorum` and
`verify_anchor_signature`. Existing `verify_bundle(bundle, trusted_root)` calls remain supported;
pass `anchor_policy`, `resolve_anchor_key` and optionally `anchors`/`external_keys` for anchoring.

The five language verifiers support the same receipt and audit verification features, pinned by
`canonical-vectors.json`, `ledger-vectors.json` and `verifier-parity-vectors.json`:

- DIV approval/offline/delegation receipts, agent-authority seals (§5b), and platform receipts (§5c).
  Platform receipts require WebAuthn and caller-pinned digest, RP, nonce, origin and subject keys.
  Authority/delegation verification never substitutes for approval of an action.
- Self-certifying DIDs, with explicit caller key mappings taking precedence.
- DEWP single-event and multi-event proof bundles: inclusion, canonical content/header binding,
  embedded ES256 signatures, tenant identity, sequence gaps/duplicates and claimed range endpoints.
- Checkpoint continuity (§5.4), and anchor quorum (§5.3) under the caller's policy: ES256, Ed25519,
  RSA-PSS and Rekor SET/payload verification under a separately pinned log key.

Trust inputs must come from the caller. A root carried in the bundle proves only internal
consistency; a producer's `externallyAnchored` flag is a claim, not verification. Bundle-carried
anchors can count under caller-trusted keys, but only independently fetched, checkpoint-attributed
anchors may establish divergence. For multi-checkpoint exports, key caller anchors by checkpoint ID
or root; a flat list cannot establish exact attribution across checkpoints.

Limits remain explicit: no NDJSON evidence streaming, no RFC 3161/CMS verification, and no WEBHOOK
anchor verifier. Those anchors do not count toward quorum. No implementation claims the complete
DEWP Extended Profile (§9.2). Embedded WebAuthn material is incomplete in the audit leaf; verify the
full DIV receipt separately. Offline authority verification checks the seal, not subsequent online
revocation. Verification does not consume a nonce or prove execution.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
