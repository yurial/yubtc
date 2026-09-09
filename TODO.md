# Known issues / stubs

**v0.2 COMPLETE; v0.3 COMPLETE (2026-09-08):** backend failover
(`--provider auto`, `--retries`), P2WSH + Tapscript multi-sig forms
(`--form p2sh|p2wsh|p2tr`, uniform N≤15), KAT test-profile speedup,
C4 enforced (timeout 5s), full spec-vs-code audit. yubtc `ea4a8c4`,
yubtc-python `acdac55`.

## Open

- **Remove `continue-on-error` from `.github/workflows/codeql.yml`**
  once the repository is made public (owner decision 2026-09-05);
  until then Code scanning is unavailable for a private repo and the
  step self-tolerates.
- **Green CI run on the squashed history** — GitHub Actions quota is
  exhausted until Oct 1 (private repo); current HEAD verified locally
  (Rust 996+, Python 1007, JVM 72, cov-gate 100/100). After quota
  reset / repo publication: verify ci + CodeQL on `ea4a8c4`, then tag
  the stable `v0.2.0` (release pipeline: CLI + APK in one run).

History of closed items — in git log and `specs/spec.md`.
