# Changelog

All notable changes to `intyga-sdk` (Python) are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

- **DIV/DEWP 1.0 pre-release correction (2026-09-27 review L15-L18, I7, I8):** signed timestamps use one
  strict RFC 3339 grammar (`datetime.fromisoformat` accepted a bare date as a naive datetime, a
  zone-less time and a space separator). `stable_stringify` refuses a string with an unpaired
  surrogate (`NonCanonicalValue`, DIV §4.1). A WebAuthn `topOrigin` differing from `origin` is
  refused. `verify_platform_receipt` ignores `require_user_verification=False`. A key mapped to two
  DIDs counts once toward a quorum. RSA-PSS anchors require a 32-byte salt and a 2048-bit modulus
  (was `PSS.AUTO`). Divergence evidence is held to the quorum's seq-range and witness-time rules; a
  Rekor entry establishes divergence only with submitter keys pinned. Pinned in all five languages by the `verifierInputHardening` parity vectors; no canonical bytes change for valid input.
- **DIV 1.0 pre-release correction (H1):** `verify_approval_receipt`, `verify_delegation` and
  `verify_agent_authority` accept `expected["requirement"]` (`{"requiredApprovals": int,
  "requesterCannotApprove": bool, "requireHardwareKey": bool}`); export `WEAKER_REQUIREMENT_REASON`.
  The signed `requirement` is authored by the signers, so one approver (possibly the requester) could
  self-compose a 1-of-1 receipt for a 3-of-3 four-eyes action and it verified. A weaker signed
  requirement is now refused before any signature is counted when the caller supplies its own rule
  (DIV §5 step 3d), on approval, offline, delegation and agent-authority verification; the reason
  starts "signed requirement is weaker than the relying party's policy". Omitting the floor keeps the
  previous behaviour, which proves only the quorum the signers stated. No signed byte changes; shared
  parity vectors pin it in all five languages.
- **DEWP evidence verification (1.0 pre-release correction, Sep 2026):** an entry with a canonical
  preimage reads `tenantSeq` only from it (None ⇒ no counter) and fails when its redaction counter
  disagrees; a tenant-bound entry fails when the bundle declares no tenant; a preimage under an
  unknown profile fails; repeated leaves/seqs and inconsistent leaf counts fail; a checkpoint with no
  `chainHash`/`anchoredAt` is never anchored. New `verify_evidence_bundle(trusted_checkpoints=...)` and
  `verify_bundle(trusted_checkpoint=...)` take caller-held roots-file records; a single proof counts a
  Rekor/TSA anchor only against one. `is_well_formed_anchor` requires a registered algorithm. Pinned
  by the shared `dewpEvidenceHardening` vectors.
- **DIV 1.0 pre-release correction (PK-11):** under a signed `requireHardwareKey`, a WEBAUTHN witness
  whose signed authenticatorData carries the Backup Eligible or Backup State flag no longer counts
  toward the quorum (DIV §4.4.5 rule 6) — a relying party now catches an issuer that let a synced
  passkey sign a hardware-pinned action. No signed byte changes; shared parity vectors pin it in all
  five languages.
- **Breaking (DEWP 1.0 pre-release correction):** the anchored preimage is now
  `[dailyRoot, timestamp, issuer, algorithm, seqStart, seqEnd, chainHash]`; anchors lacking the
  position fields never verify. External witness times (Rekor `integratedTime`, TSA `genTime`) must
  fall within `maxAnchorLagSeconds` (default 86400) after — or 300 s before — the checkpoint's claimed
  time; anchors must match the checkpoint's seq range, chain hash and `anchoredAt`; evidence-bundle
  chain hashes are recomputed; verdicts expose per-issuer witness times; an optional pinned Rekor
  submitter key is enforced. A supplied root is reported as `rootSource: "caller-supplied"` (was
  `"independent"`).
- A non-empty `allowedAaguids` is refused exactly like `requireHardwareKey`: bare-key witnesses do not
  count and offline proofs are rejected (DIV §4.3.2/§5a.3).

- Add opt-in RFC 3161 TimeStampToken verification through OpenSSL 3, with caller-pinned TSA
  certificate/CA trust, explicit offline CRL or unchecked revocation, and quorum/bundle integration.
- Scope Rekor log-key trust to one issuer for multi-issuer policies; legacy unscoped keys remain
  accepted only when the policy trusts exactly one issuer.

- Enforce DIV §5 identity trust for multi-approver quorums; preserve DIV §4.4.2 ES256
  compatibility for absent/null/unknown witness labels, while refusing AUTO_APPROVED witnesses.
- Validate DEWP protocol, version and declared hash/serialization/Merkle algorithms before
  accepting proof or evidence bundles. Legacy numeric revisions 1/2 remain supported without
  a protocol declaration. Shared cross-language fixtures cover these contracts.
- Preserve challenge-issued agent context through approval polling for DIV continuity checks.
- Public witness lookups require no credentials and refuse non-success HTTP responses.
- Default HTTP transports use finite request timeouts and refuse redirects; caller-supplied
  transports remain the caller's responsibility.

- **Wire format: DIV v1 agent intents now sign `action`, `agent`, `session`, `nbf`, and `exp` instead of ordinary `expiresAt`; `div-agent-authority` requires `parentReceiptHash` (null for a root).** Older §5b seals lacking that key cannot verify under this pre-release profile and must be re-sealed. All canonical producers, five verifier ports and vectors must move together; the ordinary HUMAN/SERVICE intent keeps `expiresAt`.

- **Wire format: the DIV Intent Payload gained a REQUIRED `evidence` field, and it must be `null`.**
  `div-intent-verification` and `div-offline-intent` now carry `"evidence":null` in the signed bytes
  (DIV §4.3.4); `div-delegation`, `div-agent-authority` and `div-platform-intent` deliberately do
  not. `null` is signed and load-bearing, exactly as `requester.attestation`'s null is: it is the
  payload's explicit statement that the authorization was not conditioned on any external fact.
  Verification refuses a payload whose `evidence` key is absent, and refuses any non-`null` value
  rather than treating it as unconditioned — the same fail-closed-on-unknown rule as the
  `signerClass` registry, and checked before Local Payload Reconstruction so an unsupported payload
  shape does not surface as a parameter mismatch. Absent and `null` are distinguished explicitly;
  collapsing them would make the check a no-op. All golden vectors were regenerated.

- Align cross-language receipt and audit verification: platform receipts, agent-authority seals,
  self-certifying DID trust, single/multi-event bundles, embedded ES256 signatures, tenant sequence
  checks, checkpoint continuity, anchor quorum and Rekor. Shared executable fixtures cover valid
  artifacts and refusals; no wire format changes.
- Refuse unknown witness signature algorithms. Require identity-bound trust when the signed
  `requesterCannotApprove` rule is set; key-only trust cannot enforce requester identity.
- **`verifyRootsChain` range-checks the FIRST entry.** The non-integer and self-inverted seq-range
  checks were gated on having a predecessor, so the first entry was never range-checked — and a
  single-entry `roots.jsonl` (a new tenant, or the first day after a truncation) is exactly where
  the first entry is the only one. Such a file verified clean here while Go and Rust refused it.
  Only the overlap check is relational now. New `single-entry-inverted-seq-range` and
  `single-entry-non-integer-seq-range` parity vectors pin it in all five ports.

- **Close approval-flow transport and argument races.** The callable guard now validates and
  detaches one canonical-JSON snapshot before its first await, then uses that snapshot for the
  challenge, local receipt verification, nonce consumption and execution. The wrapped function
  therefore receives JSON types: a tuple arrives as a list and an integral float such as `1.0` as
  the int `1`. Arguments with no portable JSON form (NaN, `-0.0`, integers outside the portable
  range) are refused before any challenge is created. Authenticated HTTP
  requests refuse redirects, so Basic and bearer credentials cannot be forwarded to another
  origin. `require_approval` now derives the gateway TTL and monotonic local deadline from one
  duration and cancels authentication/HTTP I/O when that deadline elapses. Transport
  now uses a per-request HTTPX async client so deadline cancellation closes the connection instead
  of leaving a blocking urllib read worker. OS DNS resolution can still outlive cancellation and
  delay `asyncio.run()` shutdown; no hard process-shutdown bound is claimed.
- `authorize()` now omits `actionType` when it is unset, matching the gateway's optional-field
  schema, and the manual README flow consumes its verified nonce before executing.
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

- **Security (I11):** `IntygaClient` raises `ValueError` for a `gateway_url` that is not `https://`,
  except `http://` to a loopback host (`localhost`, `127.0.0.0/8`, `::1`) for local development.

## [1.0.0]

Initial public release.

- Async client: `authorize` / `status` / `consume` / `require_approval`; `target` is required
  (DIV Target Isolation).
- DIV canonical payloads and `verify_approval_receipt` against a caller-supplied trust anchor.
- DEWP Core primitives (§9.1) plus single-bundle verification. Deliberate, documented limits:
  `signature_verified` and `anchor_verified` are always `False` here, and the §5.4 checkpoint
  chain is TypeScript-only — see the README's "DEWP conformance" section.
