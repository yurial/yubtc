# Known issues / stubs

**v0.2 COMPLETE; v0.3 COMPLETE (2026-09-08):** backend failover
(`--provider auto`, `--retries`), P2WSH + Tapscript multi-sig forms
(`--form p2sh|p2wsh|p2tr`, uniform N≤15), KAT test-profile speedup,
C4 enforced (timeout 5s), full spec-vs-code audit. yubtc `ea4a8c4`,
yubtc-python `acdac55`.

**PUBLIC + v0.2.0 tagged (2026-09-09):** repository made public;
CodeQL `continue-on-error` dropped (code scanning is free for public
repos, first real CodeQL run green). Green ci + CodeQL on the squashed
history. Two CI assumptions fixed en route: the coverage gate is
region-granularity-sensitive, so the coverage job now pins
nightly-2026-09-05 (floating nightly-2026-09-08 counts
`.map_err(closure)?` lines by their never-fired closure bodies and
phantom-missed 11 statement-level-covered lines in psbt.rs /
wallet.rs); Kotlin bindings regenerated (4 stale UniFFI API checksums
+ doc-comment paths — would have aborted Android checksum validation).
Stable `v0.2.0` tagged: release pipeline published 5 CLI archives +
release/debug APKs, isPrerelease=false.

## Open

- (none)

History of closed items — in git log and `specs/spec.md`.
