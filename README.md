# yubtc

Console Bitcoin client. Downloads nothing, stores nothing on disk: private
keys are derived from a seed on each invocation.

This is the **Rust + Android (UniFFI)** port. The original Python
implementation lives in [`../yubtc-python/`](../yubtc-python/) and stays
the bit-for-bit reference for seed derivation, address encoding, signing,
and transaction wire format.

## Status

| Cycle | Status | What landed |
|---|---|---|
| v0.1 (Phases 0–10) | done | KDF + crypto core, wallet + network backends, CLI, Android Compose app, docs |
| v0.2 (Phases 11–15) | done | release pipeline, KAT vectors, SegWit / Taproot (BIP-143/341), PSBT (BIP-174), P2SH multi-sig |
| v0.3 | done | provider failover (`--provider auto`, `--retries`), P2WSH / Tapscript multi-sig forms (`--form`), KAT test-profile speedup |

Phase-by-phase history — in git; per-phase technical detail — in
[`specs/spec.md`](./specs/spec.md). Deferred or rejected work (Compose UI
tests, live testnet E2E, on-device seed persistence / biometrics,
Lightning, hardware wallets, Tor, WASM) — specs/spec.md,
«Отклонённые предложения» and «Безопасность: что мы НЕ делаем».

## Layout

```
yubtc/
├── core/                       # Rust crate (cdylib + staticlib + rlib):
│                               #   KDF, keys, addresses, scripts, txs,
│                               #   wallet, PSBT, multi-sig, net backends,
│                               #   UniFFI surface
│   ├── examples/kat_check.rs   # KAT round-trip harness vs yubtc-python
│   ├── fuzz/                   # libFuzzer targets (6)
│   └── tests/                  # integration tests + KAT vectors (tests/kat/)
├── cli/                        # `yubtc` binary (clap, per-command impls,
│                               #   Coin Control TUI)
├── android/                    # Kotlin / Compose app (UniFFI bindings;
│                               #   keystore.properties.example)
├── bindings/kotlin/            # generated UniFFI facade (CI drift gate)
├── scripts/cov-gate.sh         # coverage gate (lines + branches = 100%)
├── specs/                      # spec.md (technical spec), UI.md (Android UI)
├── .github/workflows/          # ci.yml, codeql.yml, fuzz.yml, release.yml
├── CONTRIBUTING.md             # conventions, git workflow, recipes
├── TODO.md                     # open items
└── LICENSE                     # YSAL-1.0
```

## Quick start

### Prerequisites

- **Rust** stable toolchain (`rustup default stable`).
- **Python ≥ 3.9** with [`yubtc-python/`](../yubtc-python/) checkable
  out for the cross-compat harness.
- For Android: **JDK 17** + **Android SDK API 34** + **NDK r27**.

### Workspace

```sh
cargo build --release --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

The same commands run in CI (`.github/workflows/ci.yml`).

### CLI

```sh
cd cli && cargo build --release
./target/release/yubtc --help
./target/release/yubtc newseed
./target/release/yubtc address   # prompts: seed, passphrase
./target/release/yubtc send 1BoatSLRHtKNngkdXEeobR76b53LETtpyT 0.001 --broadcast
```

```
yubtc newseed                       # generate a fresh BIP-39 seed
yubtc address                       # receive address for (seed, nonce)
yubtc balance                       # wallet balance + UTXOs
yubtc send ADDR AMOUNT              # build, sign, optionally broadcast
yubtc send -i ADDR AMOUNT           # open the Coin Control TUI before send
yubtc dumpprivkey                   # WIF for the active address
yubtc pushtx                        # broadcast a raw tx from stdin
yubtc psbt create|sign|combine|finalize|extract|decode   # BIP-174 pipeline
yubtc ms create N M                 # quorum address (N M mandatory; --form)
yubtc ms send ADDR AMOUNT N M       # quorum PSBT → cosign via the psbt pipeline
```

Global flags (where applicable): `--provider NAME` (default
`blockchain.info`; alternatives: `blockstream`, `mempool.space`, `auto`
— v0.3 failover across the three; `mock` for tests), `--retries N`
(per-request retries, v0.3), `--kdf NAME` (`auto` / `yubtc` / `pbkdf2`
/ `argon2id` / `scrypt`), `--addr-type native|taproot|legacy` (default
`native` — P2WPKH `bc1q…`; `legacy` reproduces the v0.1 P2PKH
encoding), `-n NONCE`, `-c CONFIRMATIONS`, `-k FEE_KB`, `--broadcast`,
`-y / --yes`, `-i / --interactive`, `ms --form p2sh|p2wsh|p2tr`
(default `p2sh`). `send` accepts `bc1…` recipients (P2WPKH `bc1q…` and
P2TR `bc1p…`; P2WSH is rejected with a typed error). Full command
surface — specs/spec.md, «CLI — команды».

Seed reception is **permissive by default** (any non-empty phrase; a low
entropy estimate only warns). `--strict-bip39` — on the seed-taking
commands `address`, `balance`, `dumpprivkey`, `send`, `psbt create`,
`psbt sign`, `ms create`, `ms send` — opts into strict reception: full
BIP-39 parse (wordlist + checksum) plus the entropy floor, with a
blocking rejection before any KDF work (specs/spec.md, «Seed policy»).

Passphrase comes from an interactive prompt (`getpass` on a TTY,
line-read on a piped stdin). There is no `--passphrase` flag — the
wallet is the secret.

### Android

```sh
# 1. Cross-compile the Rust cdylib for each ABI
for triple in aarch64-linux-android armv7-linux-androideabi x86_64-linux-android; do
  cargo build --release --target $triple -p yubtc-core --lib
done

# 2. Stage the .so files and build a debug APK (no keystore needed)
cd android && ./gradlew copyNativeLibs && ./gradlew assembleDebug
```

A distributable release APK additionally reads
`android/keystore.properties` (gitignored; template:
`android/keystore.properties.example`); when the file is absent or any
field is blank, the build falls back to the debug keystore — it still
succeeds, but the APK is **not** suitable for distribution. In CI the
`apk` job materialises the file from the `YBTC_KEYSTORE_PROPERTIES`
repository secret. Android CI checks (3-ABI build matrix, bindings
drift, JVM unit tests, APK assembly) run in the release pipeline only
(`.github/workflows/release.yml`, tag `v*`).

### Fuzz

```sh
cd core && cargo +nightly fuzz run fuzz_wif -- -max_total_time=60
```

CI runs every target for 60 s in the nightly fuzz workflow
(`.github/workflows/fuzz.yml`).

## Cross-compat harness

The Rust core is proven bit-for-bit against the Python reference via
subprocess harnesses — a KAT round-trip (`core/examples/kat_check.rs` ↔
`yubtc-python/tests/test_xcompat.py`) and a CLI xcompat mock-backend
comparison — plus frozen KAT vectors in `core/tests/kat/` (all 4 KDFs,
PSBT, multi-sig; no subprocess needed). Recipes — `CONTRIBUTING.md`
(«Как добавить новый KDF»); the CI-side gates — `specs/spec.md`
(«Качество и CI»).

## Quality gates

- Coverage gate: **100% lines AND 100% branches** (nightly
  `cargo-llvm-cov` + `scripts/cov-gate.sh`).
- `clippy -D warnings`, `cargo fmt --check`, `cargo geiger` (no
  `unsafe` in our code), `cargo audit`.
- Bit-for-bit cross-compat against `yubtc-python` on every PR (see
  above).
- Android JVM unit tests — in the release pipeline.

Full pipeline, zero-`unwrap` / no-silent-fallback policies and the CI
workflow table — `specs/spec.md`, «Качество и CI»; conventions —
`CONTRIBUTING.md`.

## Documentation

- [`specs/spec.md`](./specs/spec.md) — technical spec: KDF, addresses,
  fee loop, network backends, PSBT / multi-sig, CLI surface,
  Android / UniFFI, quality & CI, project governance.
- [`specs/UI.md`](./specs/UI.md) — Android UI reference (screens,
  transitions, state contract).
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — conventions, git workflow,
  recipes (new network backend / KDF), Python-mirror rules.
- [`SECURITY.md`](./SECURITY.md) — vulnerability reporting, scope,
  design notes, CI security gates.
- [`TODO.md`](./TODO.md) — known issues and open items.

## License

YBTC Limited Source-Available License v1 (YSAL-1.0). See [`LICENSE`](./LICENSE).
Имя лицензии (`v1`) — внутренняя версия YSAL, не привязана к MAJOR
релиза (v0.1 / v0.2 — см. `specs/spec.md`, «Управление проектом →
Версионирование»).
The Python reference implementation under [`../yubtc-python/`](../yubtc-python/)
stays MIT.
