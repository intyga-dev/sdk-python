# sakra-sdk — Universal Governance for Automated Operations (Python)

One SDK for every SÄKRA use case, implemented in Python.

## Installation

```bash
pip install .
```

## Require a human approval before a high-risk action

```python
import asyncio
from sakra_sdk import SakraClient

async def main():
    sakra = SakraClient(
        gateway_url="https://api.sakra.com",
        client_id="your-client-id",
        client_secret="your-client-secret"
    )

    # Blocks until the human approves with their passkey / security key (or times out):
    r = await sakra.require_approval("Delete production database")
    if r["status"] != "APPROVED":
        raise Exception("not authorized")
    
    # safe to proceed!

if __name__ == "__main__":
    asyncio.run(main())
```

## DEWP conformance

`sakra_sdk.ledger` implements the **DEWP Core primitives** ([`docs/DEWP.md`](../../docs/DEWP.md) §9.1) —
domain-separated hashing, two-tier Merkle construction, inclusion proof verification, the
`trust.sakra.audit.v1` canonical preimage, the `0x03` anchor digest — plus single-bundle verification
with the §7.1 property model (`verify_bundle`). Parity with the TypeScript reference is locked by the
shared golden vectors in `packages/mcp-schemas/vectors/ledger-vectors.json`.

Two limits are deliberate and reported honestly rather than silently:

- **`signature_verified` is always `False`.** Re-verifying the embedded DIV ES256 signature would pull
  a cryptography dependency into a module that otherwise needs only `hashlib`. A signed event therefore
  reports `CONTENT_VERIFIED` here where the TypeScript verifier would report `SIGNATURE_VERIFIED` — the
  commitment result is identical; only the signature claim is withheld.
- **Anchor signature and quorum verification (§5.3) are not implemented.** `anchor_digest_hex` is
  provided, but `anchor_verified` reflects only whether an independent root was supplied.

For the Extended Profile — signed multi-anchor quorum, evidence bundles and gapless `tenantSeq`
validation — use the TypeScript verifier (`@sakra-trust/verify`).

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
