# Changelog

All notable changes to `intyga-sdk` (Python) are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

- `require_human_approval` (`intyga_sdk.guard`) — gate any sync/async callable behind a signed
  human approval; the integration surface for LangChain / CrewAI style frameworks (they consume
  plain callables). Positional arguments are refused so every signed parameter is named.
- Typed exceptions (`intyga_sdk.errors`): `IntygaError`, `GatewayRefused` (with `.status`),
  `GatewayUnreachable`, `ApprovalRefused` — replacing bare `Exception` raises. All subclass
  `Exception`, so existing handlers keep working.
- `require_approval()` now merges the challenge `nonce` into every result (terminal and EXPIRED),
  matching the TS/Go/Rust ports — previously the one-shot helper's caller could not feed
  `verify_approval_receipt` or record redemption.
- PEP 561 `py.typed` marker shipped.

## [1.0.0]

Initial public release.

- Async client: `authorize` / `status` / `consume` / `require_approval`; `target` is required
  (DIV Target Isolation).
- DIV canonical payloads and `verify_approval_receipt` against a caller-supplied trust anchor.
- DEWP Core primitives (§9.1) plus single-bundle verification. Deliberate, documented limits:
  `signature_verified` and `anchor_verified` are always `False` here, and the §5.4 checkpoint
  chain is TypeScript-only — see the README's "DEWP conformance" section.
