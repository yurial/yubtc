# Security Policy

## Supported versions

Only the latest tagged release and `master` receive security fixes.
Older tags are not maintained.

| Version | Supported |
|---|---|
| latest release / `master` | ✅ |
| older tags | ❌ |

## Reporting a vulnerability

**Do NOT open a public GitHub issue for security reports.**

Use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on this repository, or contact
the maintainer directly if you cannot use it.

Please include:

- affected component and version (crate `yubtc-core`, `yubtc` CLI,
  Android APK, or the Python reference mirror);
- a minimal reproduction (seed phrase must be a throwaway test seed —
  never send a real one);
- expected vs actual behaviour;
- your assessment of impact.

### Response targets

- acknowledgement: **72 hours**;
- triage / severity assessment: **7 days**;
- fix or mitigation: **30 days** for high/critical findings,
  next release cycle otherwise.

We will credit reporters in the release notes unless they prefer to
remain anonymous.

## Scope

### In scope

- the Rust workspace (`core/`, `cli/`) and the Android app (`android/`);
- the Python reference mirror (`yubtc-python`, same owner) **only**
  where it affects the Rust/Android products (KDF parity, parsing,
  cross-compat behaviour);
- cryptographic constructions as documented in `specs/spec.md`
  (KDFs, key derivation, signing, address encoding, PSBT, multisig).

### Out of scope

- the stateless-by-design model itself (seed is never persisted) —
  documented design, not a finding;
- exhaustive host compromise, clipboard sniffing, screen recording and
  similar end-user-environment attacks;
- the coin/feerate assumptions of network backends (they are
  untrusted data sources by design; a hostile backend can DoS a scan
  but cannot forge signatures or spend funds);
- missing SegWit/other address-form support that `specs/spec.md`
  lists as out of scope.

## Design notes for reviewers

- The wallet is **stateless**: keys are derived from the user's seed
  on every invocation, nothing is persisted. `wipe-on-lock` drops the
  wallet handle when the Android app backgrounds.
- Fixed KAT fixture values (test seeds, pinned hex) live in
  `#[cfg(test)]` modules only and are compiled out of release
  artifacts. CodeQL `hard-coded-cryptographic-value` findings on those
  lines are expected and dismissed as test-only.
- Production key material is never hard-coded: private keys are
  derived from the user's seed phrase at runtime; the only fixed
  cryptographic constants are public protocol constants (NUMS point,
  salt tags, BIP tags) documented in `specs/spec.md`.

## Cryptography disclosure

- ECDSA (secp256k1) via `k256`; BIP-340 Schnorr via `k256` (`schnorr`);
  signing primitives are upstream crates, not custom code.
- Known accepted trade-offs are recorded in `specs/spec.md`
  (e.g. deterministic `aux_rand = 0x00 × 32` for Schnorr reproducibility,
  legacy `yubtc` cascade clamp per decision C1, scrypt v2 salt tag per C5).

## CI security gates

- `cargo audit` (RustSEC advisories) — advisory job in `ci.yml`;
- `cargo geiger` — `unsafe` count reported per push (our crates: 0);
- CodeQL — every push/PR; findings in test modules are triaged as
  described above;
- Dependabot alerts + security updates — enabled;
- secret scanning + push protection — enabled.
