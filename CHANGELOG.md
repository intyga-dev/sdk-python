# Changelog

All notable changes to `intyga-sdk` (Python) are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

- **Tokens are re-exchanged before they expire, and once more on a 401.** `IntygaClient` cached
  the first `client_credentials` exchange for the life of the process and never read `expires_in`,
  so a long-lived service (the `require_human_approval` guard holds one client) or a long
  `require_approval` poll died at the gateway's TTL with a bare `GatewayRefused(401)` and stayed
  dead until restart. The client now honours `expires_in` on a monotonic clock — the cache is served
  only while more than `min(60 s, expires_in / 10)` of it remains, then exchanged again — and a 401
  against a token it exchanged itself clears the cache and retries exactly once (clock skew, a
  gateway-side TTL change). An explicit `token` is never retried: it has nothing to re-exchange
  with. An absent or non-numeric `expires_in` keeps the old cache-until-401 behaviour. This is what
  lets the gateway shorten agent/human token lifetimes.
- **A stored `intyga login` credential says how to fix itself.** It cannot be refreshed (no
  secret), so its JWT `exp` is now read — unverified, a hint for the message only — and an expired
  one, or a 401 the gateway returns for it, raises `GatewayRefused(401)` telling you to run
  `intyga login` again instead of surfacing the raw rejection; the cache is cleared so a fresh
  login is picked up on the next call.
- **`require_human_approval` can now verify the receipt (DIV §5).** It decided on the gateway's
  `status` string alone: it never read `receipt`, never checked a signature, and never redeemed the
  nonce — so the gateway's word was the only thing between an agent and an irreversible action, in
  the SDK's only action-executing path. Pass `approvers` (plus `expected_origin` / `expected_rp_id`
  for a passkey witness) and the guard re-derives the canonical payload from the target and kwargs
  it is about to execute, verifies the signatures against YOUR keys, refuses a result carrying no
  receipt, and consumes the nonce before calling the function. Omitting `approvers` keeps the old
  behavior for compatibility and now warns at decoration time instead of being silent about it.
- **Refuse an omitted `expected['actionType']` or `expected['params']` (DIV §4.4.1).** Both
  defaulted to `""`/`{}`, so a caller who omitted or misspelled either key — easy in an untyped
  dict API — rebuilt a payload bound to nothing and got `ok: True` against a receipt minted with
  those same empty values. An explicitly written `""`/`{}` is still accepted; only omission is
  refused. Applies to `verify_delegation` as well.
- **DEWP root selection now mirrors the TypeScript reference's fallback chain.** Only
  `anchor.dailyRoot` was read, but the reference producer omits `anchor` entirely until signed
  anchors exist — so the ordinary console export reported `INVALID`, the verdict that reads as
  tampering, for an untampered bundle. `legacyAnchor.dailyRoot` and `proof.checkpointRoot` are now
  read after it, still as `rootSource: "self-asserted"` and still not `ok`.
- **A redacted, commitment-only bundle is `ok` again at `COMMITMENT_VERIFIED` (DEWP §15).** `ok`
  required a leaf binding, which an export carrying no preimage cannot supply by design. A
  prover-supplied unknown `profile` over content the bundle DID ship still disqualifies.
- **`verify_inclusion_proof` returns `False` for a malformed proof** instead of raising `KeyError`
  — it is a documented predicate, and only `verify_bundle`'s try/except was hiding that.
- **`verify_anchor_signature` accepts base64url** for the trusted key and the anchor signature,
  matching `@intyga/verify`. `base64.b64decode` without `validate` silently discards `-` and `_`,
  so a base64url anchor decoded to different bytes and read as an invalid signature (DEWP §5.2).
- **An `int` above the double range is a `NonCanonicalValue` refusal, not an `OverflowError`,**
  out of `stable_stringify` / the canonical payload builders.
- Build-system pin raised to `setuptools>=77.0.0` — the PEP 639 `license` / `license-files`
  metadata this project declares cannot be built by anything older.
- **Refuse a forward-dated offline proof or delegation (DIV §5a.3 rule 3, §5a.6 step 1).** The
  window caps bounded a proof's WIDTH but never its POSITION, so a quorum-signed proof dated years
  ahead with a compliant 60-minute (or 72-hour) window verified today and kept verifying until that
  date. The check is unconditional — the audit/`allow_expired` override re-examines a proof that was
  valid and has lapsed, and does not reach one dated in the future.
- **Refuse a signed `requirement.requiredApprovals` below 1 (DIV §4.3.2).** §5 step 7's "at least
  `requiredApprovals`" is satisfied vacuously by 0, so the minimum is now enforced explicitly
  instead of by an undocumented floor.
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
