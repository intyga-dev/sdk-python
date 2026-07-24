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

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
