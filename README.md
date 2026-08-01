# intyga-sdk — Universal Governance for Automated Operations (Python)

One SDK for every Intyga use case, implemented in Python.

## Installation

```bash
pip install .
```

## Require a human approval before a high-risk action

```python
import asyncio
from intyga_sdk import IntygaClient

async def main():
    intyga = IntygaClient(
        gateway_url="https://api.intyga.com",
        client_id="your-client-id",
        client_secret="your-client-secret"
    )

    # Blocks until the human approves with their passkey / security key (or times out):
    r = await intyga.require_approval("Delete production database")
    if r["status"] != "APPROVED":
        raise Exception("not authorized")
    
    # safe to proceed!

if __name__ == "__main__":
    asyncio.run(main())
```

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
