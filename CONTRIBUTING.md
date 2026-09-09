# Contributing to yubtc (Rust + Android port)

Конвенции, workflow и рецепты для разработки в этом репозитории.
Документ самодостаточен и опирается на правила ниже: 100% line +
branch coverage, newtype для магических типов, никаких silent
fallbacks. Для Python-зеркала (`yubtc-python`) действует
дополнительный набор конвенций — см. § «Зеркало yubtc-python:
конвенции».

## Git workflow

- **Каждая задача — в worktree.** `git worktree add ../<issue-name> -b
  issue-<name>`. Не коммитьте в `master` напрямую — открывайте
  ветку под issue и PR в `main`.
- **Precommit + build-ok.** Договорились: каждый значимый
  changeset коммитится как `precommit`; после успешного
  `cargo test` + `cargo clippy -D warnings` + `cargo fmt --check`
  эти `precommit` объединяются в один commit `build-ok`. Финальный
  commit на завершение подзадачи — отдельный, с развёрнутым
  описанием «что и зачем» (см. стиль существующих T3/T4 коммитов).
- **Не используйте `--force` в `main`/`master`.** Для feature-веток
  force с `--force-with-lease` допустим, если вы уверены, что
  локальная история полна.
- **Сообщения коммитов** — в развёрнутом стиле (не «fix bug»),
  объясняющем *почему*, а не *что*. Ссылайтесь на спец-символы и
  файлы: `phase 9 T3: LockScheduler re-checks isWipeEnabled() inside
  the launched block (settings toggle race)`.

## Конвенции Rust

### Архитектурные правила (non-negotiable)

- **100% line coverage** на каждом PR. CI гейт
  `cargo-llvm-cov --fail-under-lines=100`. Branch coverage — в TODO.md
  как известный gap (requires nightly `cargo-llvm-cov --branch`).
- **Никаких `unwrap()` / `expect()` в production коде.** Только в
  тестах и в fuzz-harness'ах, где panic — это success-path.
- **Никаких `panic!()` в production.** Все error path'ы — типизированные
  `thiserror` enum'ы. Conversion в `anyhow::Result` допустим только в
  CLI (`cli/src/main.rs`) — ядро возвращает `Result<T, ThisError>`.
- **`unsafe` запрещён** в нашем коде (`cargo geiger = 0`). `unsafe`
  в upstream `bitcoin` / `k256` / `bitcoin-secp256k1` — задокументирован
  в `Cargo.lock`.
- **Newtype для всех magic types.** См. `core/src/misc.rs`:
  `TSatoshi(u64)`, `TAddress(String)`, `TNonce(u32)`, `TSeed(String)`,
  `TPassphrase(String)`, `TBTC(Decimal-equivalent)`. Никаких
  голых `u64` для сатоши, никаких `String` для адресов.
- **Default constants — в `core/src/fwd.rs`.** Это single source of
  truth для всех дефолтов: `DEFAULT_NONCE`, `DEFAULT_SEED_WORDS`,
  `DEFAULT_FEEKB`, `DUST_THRESHOLD_P2PKH`, etc. CLI и Android читают
  оттуда, не дублируют.
- **Никаких silent fallbacks.** Если `btcToSatoshi` не может распарсить
  строку, это `Err`, не `0`. Если backend не вернул `final_balance`,
  это `NetError::BadResponse`, не `0`.

### Тесты

- Пишутся **вместе с кодом** в каждой подзадаче (см. § Тесты).
  Отдельных "test phases" нет.
- Структура: unit-тесты в `#[cfg(test)] mod tests` в каждом модуле;
  integration — в `core/tests/` (чистый black-box через public API);
  property — через `proptest!`; число cases — по конфигам в коде
  (proptest default 256; overrides: 1000 у bech32/сериализации/PSBT/
  R-MS-4, 64 у fee-loop/clamp);
  fuzz — в `core/fuzz/fuzz_targets/` (libFuzler harnesses).
- Каждый fuzz harness пинает regression-тестом: после фикса бага
  добавляется тест с тем входом, который его воспроизводил (см.
  TODO.md «base58-0.2.0 underflow panic»: три regression-теста).
- Cross-compat: новые KDF/крипто-операции **обязаны** иметь
  bit-for-bit тест против yubtc-python (см. «Как добавить новый
  KDF» ниже).
- `ntest::timeout` обёртка для тестов с `tokio::test` — 5 секунд.
  Deadlock в async-тесте должен падать, а не висеть.

### Style

- `rustfmt` через `rustfmt.toml` (в корне). CI гейт
  `cargo fmt --all -- --check`.
- `clippy::pedantic` для crypto-кода (`core/src/{kdf,privkey,address,
  script,transaction,wallet}.rs`); для остального — стандартный
  clippy с `-D warnings`.
- Doc-комментарии обязательны для **публичных** API:
  - первый абзац — краткое описание (что это, когда звать);
  - второй — контракт (допустимые значения, возвраты, error'ы);
  - третий — edge cases, race conditions, UB.
  См. примеры в `core/src/wallet.rs:WalletHandle::lock`,
  `core/src/address.rs::base58_decode`, `android/.../data/Bip21Uri.kt`.
- Имена модулей snake_case, типов — PascalCase, констант —
  SCREAMING_SNAKE_CASE, generic-параметры — один символ в верхнем
  регистре (`T`, `K`, `V`).

### Кросс-компиляция и ABI

- `k256` (RustCrypto pure-Rust secp256k1) — единственный sign
  provider. **Не добавляйте** `secp256k1`/`secp256k1-sys` — это
  C-зависимость, ломает Android NDK build.
- Bitcoin crate: текущий pin `bitcoin ≈ 0.31`. Не обновляйте
  major-версию без перепрогона всех KAT — некоторые wire-format
  детали могут сместиться.
- Android cdylib: `cargo build --target <triple> -p yubtc-core
  --lib` для каждого из `aarch64-linux-android`,
  `armv7-linux-androideabi`, `x86_64-linux-android`. Линкер —
  из NDK r27 (матрица линкеров — в `release.yml`, джоба
  `build-rust`).

## Конвенции Kotlin / Compose

### Архитектурные правила

- **Single source of truth — `YubtcViewModel.state: StateFlow<YubtcState>`.**
  Экраны stateless; читают через `collectAsState()` в
  `YubtcNavHost`, передают лямбды. Не дублируйте state в `remember`.
- **`viewModelScope.launch { try { ... } catch (YubtcException) { ... } }`**
  — единственный путь вызвать UniFFI. Никакого прямого доступа к
  `WalletHandle` с Compose-слоя.
- **Без JNI-handle escape.** `WalletHandle` не покидает VM.
  Сохранение ссылки в `remember { mutableStateOf(handle) }` —
  строгая ошибка (handle уничтожается в `onCleared`).
- **LockScheduler имеет обязательный конструктор-параметр `scope: CoroutineScope`.**
  Не используйте `GlobalScope` — `@DelicateCoroutinesApi` плюс
  supervised-сема не выдерживается.
- **DI через конструкторы, не через service locator.** Пример:
  `LockSchedulerTest` создаёт `TestScope(StandardTestDispatcher(...))`
  и подсовывает фейковые `lock`/`isWipeEnabled`/`getIdleMillis`.
- **Compose-экраны принимают лямбды, не саму VM.** Это позволяет
  переиспользовать экран в `instrumented` тестах (T6 — v2+) с
  фейковой VM.

### Тесты

- **JVM unit-тесты в `app/src/test/java/`.** Каждый data-класс
  (`Bip21Uri`, `LockScheduler`, `SettingsRepository`) имеет
  отдельный `*Test.kt` с `kotlinx.coroutines.test` для
  корутин. Эти тесты гоняет CI-джоба `unit-tests`.
- **Robolectric / Compose UI tests — v2+.** См. specs/spec.md
  «Отклонённые предложения». На текущем этапе Compose
  покрыт только статическим review + APK-сборкой в CI.
- **Тесты на парсинг — Table-driven.** Каждый случай =
  один `@Test` с явным `assertEquals(expected, actual)`. Не пишите
  один большой `forEach { ... }` — флапает и плохо читается в отчёте.

## Зеркало yubtc-python: конвенции

Этот репозиторий — Rust-порт оригинала `yubtc-python`; bit-for-bit
совпадение derivation seed'а, адресов, подписи и wire format'а
держится cross-compat/KAT-харнессом (README «Cross-compat harness»).
Изменения в Python-зеркале, сопровождающие KAT-векторы, связаны теми
же правилами.

### Дисциплина миграций

- При замене самописного модуля на third-party библиотеку
  удаляются только те функции, которые библиотека действительно
  реализует. Нельзя удалять protocol-specific логику в
  предположении, что библиотека её покрывает: например, Bitcoin
  transaction hashing — это `double-SHA256`, а не `ECDSA`, и
  примитив подписи `coincurve` этот префикс не включает.
- Если миграция пошла не туда — полный rollback. Частично
  «спасать» неудавшуюся миграцию нельзя: откат целиком — дефолт.

### Quality gates (Python)

CI зеркала гейтит:
- 100% line + branch coverage (`fail_under = 100` в
  `pyproject.toml`);
- `flake8 --max-line-length=120` по `src/yubtc` и `tests`.

Если какой-то guard в зеркале ослаблен — это осознанное изменение,
а не ошибка, которую надо откатить.

### API-конвенции (Python)

Эти правила уже вшиты в кодовую базу; новый код следует той же
форме:
- Обязательные аргументы — kwargs-only. Позиционный вызов даёт
  `'only kwargs allowed'`.
- Отсутствующий обязательный kwarg даёт `'X not set'`.
- Никаких silent defaults для обязательных аргументов.

### Тест-конвенции (Python)

- Тесты идут полностью оффлайн: `yubtc.net.get_address_info` и
  `get_address_unspent` подменяются monkeypatch'ем.
- Случайные источники (например, `random.SystemRandom.choices`)
  подменяются monkeypatch'ем, когда тест зависит от выбранного
  значения.
- BIP-39 wordlist закреплён тестом
  `test_generate_seed_uses_bip39_wordlist`: любое изменение
  списка — balance-breaking event.

### Workflow (Python)

- Одна задача — одно изолированное изменение. Не подмешивайте в
  фикс посторонние чистки.
- После нетривиального изменения перед отчётом о готовности
  прогоняются полный `pytest` и `flake8 src/yubtc tests
  --max-line-length=120`.

## Как добавить новый network backend

1. Реализуйте `NetworkBackend` trait (`core/src/net/mod.rs:107`):
   `p2pkh_info`, `p2pkh_unspent`, `broadcast_tx`. Каждый метод
   возвращает `Result<T, NetError>`.
2. Заведите `pub struct XBackend { … }` + `impl Default for XBackend`
   (если backend умеет работать без конфига) + `impl NetworkBackend
   for XBackend`.
3. Зарегистрируйте в `BACKENDS` compile-time registry
   (`core/src/net/mod.rs:413`-ish) — имя через `phf::Map`.
4. Добавьте `ProviderName::X` вариант в `cli/src/cli.rs:37`.
   Значение `#[value(name = "...")]` должно совпадать с registry.
5. Добавьте чип в `SettingsScreen.kt` (`BACKENDS` локальный
   list, `SettingsScreen.kt:163`).
6. Тесты:
   - unit через `wiremock` (см. существующие тесты в `net/`);
   - mock-инстанс в `ProviderName::Mock` (CLI) — для cross-compat
     harness.
7. Smoke: `cargo run --bin yubtc address --provider x` + проверить
   `final_balance` против реального API вручную (live testnet
   в CI не входит).

## Как добавить новый KDF

1. Реализуйте в `core/src/kdf.rs`: функция вида
   `pub fn x_cascade(seed: &[u8], nonce: u32, passphrase: &str)
   -> Result<[u8; 32], KdfError>`.
2. Расширьте enum `KdfAlgoName` в `core/src/yubtc.udl` (UniFFI
   surface) — это автоматически перегенерирует Kotlin-bindings
   (CI `bindings` job падает, если вы забыли).
3. Добавьте ветку в `seed2bin` (`core/src/seed.rs`) — единая
   диспетчеризация.
4. CLI: добавьте `KdfName::X` в `cli/src/cli.rs:63`. `--kdf`
   автоматически его примет.
5. **Обязательно:** KAT cross-compat. Добавьте Python-референс
   в `seed2bin` зеркала yubtc-python (`src/yubtc/crypto.py`),
   затем вектор `(seed, nonce, passphrase, "x") → 32 bytes` в
   её `tests/test_xcompat.py`. Без него PR не примет
   yubtc-python maintainer.

## Как добавить новый address type

**Out of scope v1.** yubtc принимает только P2PKH и P2SH
(specs/spec.md «Адреса»). Добавление Bech32/SegWit требует:
- `bitcoin` crate уже умеет WPKH/WSH script'ы — нужно
  только распознавание в `make_lock_script_for_address`;
- новый `address::wif_encode` / `address::wif_decode` для
  нового prefix;
- расширение `lock_script_for_address` в `core/src/script.rs`;
- новые KAT против yubtc-python (там уже есть Bech32
  поддержка — `src/yubtc/address.py` в зеркале).

## Code review checklist

- [ ] `cargo fmt --all -- --check` зелёный.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
      зелёный.
- [ ] `cargo test --workspace` зелёный; coverage ≥ 100% lines
      (`cargo llvm-cov --fail-under-lines=100`).
- [ ] Новый публичный API имеет doc-комментарий с контрактом.
- [ ] Изменения в `core/src/{kdf,privkey,address,script,
      transaction,wallet}.rs` имеют KAT cross-compat вектор.
- [ ] Изменения в `core/src/uniffi_api.rs` или `yubtc.udl`
      сопровождаются регенерацией `bindings/kotlin/` (CI
      `bindings` job это проверяет).
- [ ] Изменения в `android/app/src/main/java/.../ui/` имеют
      JVM unit-тест на VM/data-классы, если логика вынесена
      из Compose.
- [ ] Никаких `unwrap`/`expect`/`panic!` в production.
- [ ] Никаких `unsafe` (CI `cargo-geiger` = 0).
- [ ] Сообщение коммита объясняет **почему**, не **что**.
- [ ] Если изменение затрагивает лицензию/security — упомянуто
      в PR description и запрошен ревью от второго разработчика.
      **2-reviewer rule для crypto-критичных изменений:** PR,
      меняющий crypto-код (KDF, приватные ключи, подпись,
      lock-scripts) или KAT-векторы, мержится только с approve
      от второго разработчика.

## Что НЕ нужно делать

- ❌ Добавлять CI-гейты, которые не работают (см. memory:
  «Verify with the exact CI command»). Если добавляете gate —
  проверьте его локально *точно той же командой*, что в CI, на
  master-HEAD. Не доверяйте «должно работать».
- ❌ Добавлять EncryptedSharedPreferences / biometric / Tor / WASM —
  out of scope v1, см. specs/spec.md. Lightning — исключён полностью
  (решение 2026-09-02, specs/spec.md «Отклонённые предложения»).
  Multi-sig / SBT (PSBT) — фазы v0.2 (14–15); SegWit/Taproot готов
  (Phase 13).
- ❌ Добавлять `secp256k1` (C-зависимость) — ломает Android
  NDK build, исключено ещё на Phase 1.
- ❌ Менять `fwd.rs` default constants без обновления yubtc-python
  референса — расходится bit-for-bit parity.
- ❌ Регенерировать `bindings/kotlin/` без CI — локальная версия
  может отличаться от той, что соберёт `bindings` job, и CI
  упадёт. Регенерация — это CI-шаг, не локальный prep.
- ❌ Добавлять «улучшения» в код, который не менялся в задаче:
  scope = asked, не «пока я тут».