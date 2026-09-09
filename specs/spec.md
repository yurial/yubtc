# yubtc — техническая спецификация

Этот документ — детальная спецификация Rust port + Android. Содержит
полное описание модулей, алгоритмов, data types, протоколов, а также
политики версионирования и релизов. Статусы работ — в `README.md`
(Status), история — в git.

## Обзор

yubtc — консольный Bitcoin-клиент и Android-приложение. Кошелёк
**stateless by design**: приватные ключи деривируются из seed при
каждом запуске, на диск ничего не пишется (детали — «Android / uniffi
→ Безопасность»). Работает **только на mainnet** (см. «Адреса»).
`yubtc-python` — источник истины для семантики: Rust core повторяет API
1:1, но **имена модулей не обязаны совпадать** — Rust идиомы могут
требовать переименования (например, `seed.py` → `seed.rs` совпадает,
но `cli.py` → `cli/src/main.rs` + `cli/src/cmd/*.rs`).

Инварианты, не зависящие от формы адреса: все 4 KDF и seed policy
(R-1…R-7), WIF, `net/` (trait, реестр, бэкенды — адреса для них
opaque-строки), Coin Control selector, решение #10 (без account/change
обходов), backend injection, no-`unwrap`/newtype-политики.

### Module reference — Python → Rust

| yubtc-python (`src/yubtc/`) | yubtc Rust (`core/src/` + `cli/src/`) | Назначение |
|---|---|---|
| `crypto.py` | `kdf.rs` + `privkey.rs` + `address.rs` + `script.rs` + `transaction.rs` | Все crypto-операции (KDF, key derivation, signing, scripts) |
| `seed.py` | `seed.rs` | BIP-39 wordlist, seed generation, get_seed/get_passphrase (для CLI) |
| `net.py` | `net/mod.rs` (реестр + `BlockchainInfoBackend`/`EsploraBackend`/`BlockstreamBackend`/`MempoolSpaceBackend`/`AutoBackend` в одном модуле) | Network backends с общим `NetworkBackend` trait |
| `wallet.py` | `wallet.rs` | TPrivKey, Wallet, scan_inputs_until, make_transaction, fee loop |
| `select.py` | `cli/src/cmd/select.rs` + `uniffi_api.rs::default_selection` | Coin Control greedy selector |
| `fwd.py` | `fwd.rs` | Default constants: `DEFAULT_NONCE`, `DEFAULT_SEED_WORDS`, ... |
| `misc.py` | `misc.rs` | Утилиты: `btc2satoshi`, `satoshi2btc`, `NotNone`-style required-kwargs macro |
| `cli.py` | `cli/src/main.rs` + `cli/src/cmd/{newseed,address,balance,send,dumpprivkey,pushtx,psbt,ms}.rs` | CLI entry + команды (clap-based) |
| `tui.py` | `cli/src/cmd/tui.rs` + `cli/src/cmd/tui_term.rs` | TUI для UTXO picker (Coin Control interactive mode; crossterm-цикл вынесен в `tui_term.rs`) |

### Helper-функции (из `wallet.py`), требующие явного маппинга

| Python helper | Rust location | Семантика |
|---|---|---|
| `_make_vin` | `wallet.rs::build_vin` | Сборка `TxIn` из UTXO + sequence (`SEQUENCE_RBF_SIGNALED`) |
| `_select_inputs` | `uniffi_api.rs::default_selection` + fee loop внутри `wallet.rs::make_transaction` | Greedy-выбор + fee loop |
| `_scan_inputs` | `wallet.rs::scan_inputs_until` / `wallet.rs::scan_all` | Scan адресов до gap, сбор UTXO, source selection |
| `_announce_tx` | `cli/src/cmd/send.rs` (печать анонса) | Pretty-print txid/size/fee + broadcast flag |
| `_pick_best_fee_loop_candidate` | `wallet.rs::pick_best_fee_loop_candidate` | Size-keyed best-pick (см. секцию «Fee loop и dust») |

## Ключи и seed

### Библиотека подписи: k256

**Используем `k256` (RustCrypto, pure-Rust secp256k1) — НЕ `secp256k1` (FFI к C) и НЕ `secp256k1-sys`.**

Обоснование выбора:
- ✅ Pure-Rust, нет C-зависимости → один toolchain (rustc), проще CI, проще Android NDK build.
- ✅ `cargo geiger = 0` в нашем коде (никакого `unsafe` FFI в `k256`).
- ✅ Pure-Rust проще аудировать.
- ✅ Cross-compile из коробки: `cargo build --target aarch64-linux-android` без CMake/autotools.
- ✅ Deterministic builds без зависимости от версии системной libsecp256k1.
- ⚠️ Производительность: 5-10× медленнее, чем `secp256k1` FFI к Bitcoin Core. Для CLI и Android-UI это нерелевантно (любая подпись < 1 мс даже на `k256`).
- ⚠️ Edge-case совместимость: bitcoinj/core могут иметь микро-расхождения в нестандартных подписях. Для нашего use-case (P2PKH, обычные подписи) — несущественно.

**Кривые нагрузки:**
- `k256::SecretKey::from_slice(clamped_bytes)` — ~10 мкс на pure-Rust.
- Подпись ECDSA — ~50 мкс.
- Все остальные шаги (KDF, hash160, base58) — наносекунды.
- **Bottleneck не crypto, а сеть** (HTTP к mempool.space).

### KDF — детальная спецификация

**Источник истины:** фактическая реализация в `yubtc-python/src/yubtc/crypto.py` (`seed2bin`) и её зеркало `core/src/kdf.rs`. Rust port обязан выдавать **бит-в-бит тот же 32-байтовый секрет** для тех же `(seed, nonce, passphrase, kdf)`, иначе существующий seed+passphrase даст другой адрес.

Поддерживаются **4 KDF-алгоритма** (выбираются через параметр `kdf` в `seed2bin`, в CLI — через `--kdf`):

#### `yubtc` — legacy cascade (только empty passphrase)

```python
data = pack(">L", nonce) + str2bytes(seed)  # latin-1 encode
return sha256(keccak256(blake2b256(data)))
```

Bit-identical для всех кошельков, созданных без passphrase. Через PBKDF2/Argon2id/scrypt не идём **никогда** на этой ветке — это сохраняет обратную совместимость и обеспечивает, что существующий seed без passphrase открывается тем же адресом.

Применяется **только** при `passphrase == ""`. При попытке использовать другой `kdf` с пустым passphrase — ошибка `PassphraseRequired`.

#### `pbkdf2` — BIP-39 + BIP-32 + BIP-44 (default для непустого passphrase)

```python
seed_bytes = unicodedata.normalize('NFKD', seed).encode('utf-8')
pass_bytes = unicodedata.normalize('NFKD', passphrase).encode('utf-8')
stretched = pbkdf2_hmac(
    'sha512', seed_bytes,
    b'mnemonic' + pass_bytes,         # BIP-39 standard salt
    iterations=2048, dklen=64,
)
master_priv, master_chain = master_from_seed(seed=stretched)
path = "m/44'/0'/0'/0/{nonce}".format(nonce=nonce)
child_priv, _ = derive_path(
    master_priv=master_priv, master_chain=master_chain, path=path,
)
return child_priv
```

Шаги:
1. NFKD-нормализация обоих строк + UTF-8.
2. PBKDF2-HMAC-SHA512 (BIP-39 standard: salt `b'mnemonic' + passphrase`, 2048 iter, 64 byte) → BIP-39 seed.
3. BIP-32 мастер через `HMAC-SHA512(seed, b"Bitcoin seed")` → `(master_priv, master_chain)`.
4. Hardened-деривация по пути `m/44'/0'/0'/0/<nonce>` — BIP-44 main receiving chain (`purpose=44`, `coin_type=0`, `account=0`, `chain=0`, `address_index=nonce`).
5. Возврат 32-байтного child private key.

Любой BIP-39 кошелёк (Trezor, Ledger, Electrum) с теми же `mnemonic`+`passphrase` придёт к тому же адресу при том же `nonce`. **Это default для `passphrase != ""`.**

#### `argon2id` — Argon2id stretch → BIP-44 leaf → secp256k1 (опционально)

```python
seed_bytes = seed.encode('utf-8')  # raw UTF-8, без NFKD
pass_bytes = passphrase.encode('utf-8')
salt = b'yubtc-argon2id-v1\x00' + pass_bytes
stretched = argon2id(
    password=seed_bytes, salt=salt,
    time_cost=3, memory_cost=64 * 1024, parallelism=4,  # 64 MiB
    hash_len=64,
)
return bip32_leaf(stretched, nonce=nonce, purpose=44)
# 64 байта stretch → BIP-32 master → m/44'/0'/0'/0/<nonce> → 32 байта
```

Параметры зафиксированы. Salt включает version tag. 64-байтный
stretch проходит общий BIP-44 leaf-walk (`kdf.rs::bip32_leaf` /
`crypto.py::_bip32_leaf`): итог — 32 байта leaf
`m/44'/0'/0'/0/<nonce>` в secp256k1 напрямую, без clamp (sync
2026-09-07, за `0c20b8c`): Argon2id ветка использует тот же
m/44'/0'/0'/0/n leaf-walk, что и scrypt.
Wallet с `argon2id` **не совместим** ни с одним BIP-39 кошельком — это yubtc-only режим (stretch отличается от BIP-39 PBKDF2). Зато устойчивее к GPU/ASIC brute force.

#### `scrypt` — scrypt stretch → BIP-44 leaf → secp256k1 (опционально)

```python
seed_bytes = seed.encode('utf-8')  # raw UTF-8, без NFKD
pass_bytes = passphrase.encode('utf-8')
salt = b'yubtc-scrypt-v2\x00' + pass_bytes
stretched = scrypt(
    password=seed_bytes, salt=salt,
    N=1 << 15, r=16, p=1, dklen=64,
    # 64 MiB: 128 * N * r = 128 * 32768 * 16 = 67 108 864 байта = 64 MiB
)
return bip32_leaf(stretched, nonce=nonce, purpose=44)
# 64 байта stretch → BIP-32 master → m/44'/0'/0'/0/<nonce> → 32 байта
```

Параметры зафиксированы. Salt включает version tag (`v2`). 64-байтный
stretch проходит общий BIP-44 leaf-walk (`kdf.rs::bip32_leaf` /
`crypto.py::_bip32_leaf`): итог — 32 байта leaf
`m/44'/0'/0'/0/<nonce>` в secp256k1 напрямую, без clamp.
Wallet с `scrypt` не совместим с BIP-39 кошельками — это yubtc-only
режим. **Решение C5 (2026-08-17):** старые scrypt-кошельки (salt
`yubtc-scrypt-v1`, `r=8`) не открываются; пре-релиз — владелец
пересоздаёт кошельки. **Memory budget: 64 MiB** (как и `argon2id`): для скриптов с
маленькими кошельками это сопоставимо, и пользователь не должен
выбирать KDF «из соображений ОЗУ» — оба memory-hard по 64 MiB.

#### Сводная таблица

| `kdf`     | Passphrase   | Совместим с BIP-39? | KDF cost              | Использует BIP-32? |
|-----------|--------------|---------------------|-----------------------|---------------------|
| `yubtc`   | required=""  | n/a                 | мкс                   | нет                 |
| `pbkdf2`  | required     | **да** (default)    | 2048 iter PBKDF2      | да (m/44'/0'/0'/0/n)|
| `argon2id`| required     | нет                 | 64 MiB, 3 iter        | да (m/44'/0'/0'/0/n)|
| `scrypt`  | required     | нет                 | 64 MiB, N=2¹⁵, r=16   | да (m/44'/0'/0'/0/n)|

#### Selection

- **API:** `seed2bin(seed, nonce, passphrase, kdf, addr_type)`. Default
  для непустого passphrase — `pbkdf2`. Default для пустого — всегда
  `yubtc` (другие запрещены). Явный `kdf` не передан — выбирается по
  passphrase (`KdfAlgo::default_for` / `default_kdf`).
- **CLI (Rust):** `--kdf {auto,yubtc,pbkdf2,argon2id,scrypt}`,
  default `auto` — `yubtc` для пустого passphrase, `pbkdf2` для
  непустого (дореволюционное поведение). Python CLI флага `--kdf` не
  имеет — KDF выбирается автоматически по passphrase.
- **Android:** KDF-селектора нет — `YubtcViewModel` резолвит KDF по
  passphrase (empty → `yubtc`, non-empty → `pbkdf2`).

#### Свойства

- **`seed2bin(seed, nonce, passphrase="")` ≡ `seed2bin(seed, nonce)`** —
  обе ветки уходят в yubtc cascade (см. тест
  `test_seed2bin_empty_passphrase_matches_no_passphrase`).
- **`bin2privkey` clamp применяется только к ветке `yubtc_cascade`.**
  `seed2privkey_yubtc = PrivateKey(bin2privkey(seed2bin_yubtc(...)))`.
  Для `pbkdf2`/`argon2id`/`scrypt` 32 байта BIP-44 leaf идут в
  secp256k1 **напрямую**, без clamp. Причина: clamp искажает секрет, и
  для BIP-39-совместимых кошельков (Trezor / Ledger / Electrum)
  после PBKDF2 + clamp адрес перестаёт совпадать с тем, что они
  показывают для того же `(mnemonic, passphrase)`. yubtc_cascade — наш
  собственный KDF, в нём совместимости с внешними кошельками нет,
  поэтому clamp там допустим и сохраняется как bit-for-bit
  совместимость с pre-passphrase кошельками yubtc-python.
- **`chain=0` only** — мы идём по receiving chain. Cashback возвращается на следующий `nonce` той же цепи. Полный BIP-44 обход (account×change×index) — O(N×M) на scan, несовместимо с no-storage моделью.
- **Argon2id/scrypt** — деривация single-address-per-nonce; тот же seed всегда даёт тот же приватный ключ, но сменить derivation path нельзя (path закреплён: `m/44'/0'/0'/0/n`; параметр purpose для этих KDF игнорируется — вариант A, ОВ-2). Для yubtc это OK — мы всё равно фиксируем path.

### Адресная политика и nonce→path mapping

Новый enum `AddrType { Legacy, Native, Taproot }`. Default — **`Native` (P2WPKH)**; `Taproot` — opt-in; `Legacy` — через флаг (см. «Адреса → Миграция и совместимость»).

Маппинг `nonce → ключ` по KDF:

| KDF | Legacy (без изменений) | Native (P2WPKH) | Taproot (P2TR) |
|---|---|---|---|
| `pbkdf2` (BIP-39) | `m/44'/0'/0'/0/n` — как сегодня | `m/84'/0'/0'/0/n` (BIP-84) | `m/86'/0'/0'/0/n` (BIP-86) |
| `yubtc`, `argon2id`, `scrypt` (не BIP-32) | `seed2bin(seed, n, passphrase, kdf)` — как сегодня | тот же ключ, другая кодировка (вариант A, **ОВ-2**) | тот же ключ + TapTweak (вариант A, **ОВ-2**) |

- **`pbkdf2`** — все три пути деривируются от одного BIP-39 мастера (`HMAC-SHA512(seed, b"Bitcoin seed")`), все элементы hardened; `n` = address_index, без account/change обходов (решение #10 остаётся). Native/Taproot-адреса воспроизводимы внешними BIP-84/86-кошельками (Trezor/Ledger/Electrum) — тот же уровень совместимости, что у текущей `m/44'`-ветки.
- **Вариант A (рекомендация, ОВ-2)** для не-BIP-32 KDF: nonce→секрет не меняется, адрес — другая кодировка того же ключа. WIF идентичен во всех типах; траты работают одним ключом. Следствие (документируем): раскрытие pubkey при трате P2WPKH/P2TR связывает на цепи все типы адресов этого ключа — cross-type linkability. Альтернатива (вариант B): `AddrTypeUnsupportedKdf` — SegWit только для `pbkdf2`-кошельков.
- **Bit-for-bit легаси:** ни одна ветка Legacy не меняется: `pbkdf2`-путь, clamp-политика, base58check — байт в байт. KAT-матрица расширяется осью `addr_type`, при этом существующие строки `vectors.json` не пересчитываются (regression-гвард).
- Регистрация типа: параметр `addr_type` в `WalletHandle`/CLI-флаге (per-invocation; кошелёк stateless — тип не хранится). Scan видит UTXO всех форм всегда (см. «Кошелёк: UTXO-модель и scan»), тип влияет только на адрес получения/cashback.

### Seed policy — приём seed (permissive / strict BIP-39)

Strict-режим опционален (введение — `DEVIATIONS.md`, D-001); деривация
при этом не меняется: изменение — только в приёме/валидации, не в
`seed2bin` (R-7).

`TSeed` — фраза пользователя, **не обязательно** BIP-39-мнемоника.
Приём seed'а (CLI-prompt, passphrase-экран Android, импорт в
`WalletHandle`)
подчиняется правилам R-1…R-7; каждая формулировка тестируема напрямую.

#### Режимы приёма

| Режим | Включение | Проверки при приёме | Поведение при отказе |
|---|---|---|---|
| **Permissive** (default) | Default: CLI — без флага; Android — `strict_bip39 = false` | R-2 (непустота) + R-6 (warning, не блокирует) | только пустая фраза |
| **Strict BIP-39** | CLI-флаг `--strict-bip39`; Android — настройка `strict_bip39 = true` | R-2 + R-4 (BIP-39 parse + C6 entropy floor) + R-6 | блокирующий отказ до KDF |

#### Правила приёма (тестируемые)

- **R-1 (permissive default).** В permissive-режиме принимается любая
  непустая фраза пользователя — не только BIP-39-мнемоника. BIP-39
  parse (wordlist + checksum) и C6 entropy floor НЕ применяются.
- **R-2 (empty phrase).** Пустая (после trim) фраза — ошибка приёма в
  любом режиме (permissive и strict). Существующее поведение
  сохраняется: CLI отвергает на приёме; `WalletError::EmptySeed` в
  core остаётся для bindings.
- **R-3 (strict opt-in).** Strict включается только явно: CLI-флаг
  `--strict-bip39`; Android — настройка `strict_bip39` (bool, default
  `false`, хранение в `SharedPreferences` по существующему паттерну
  `Settings`). Дефолт системы — permissive.
- **R-4 (strict = BIP-39 parse + entropy floor).** В strict-режиме
  приём = полный BIP-39 parse (все слова из wordlist'а, checksum
  валиден) + C6 entropy floor (минимум уникальных слов `>= 4/5/6/7/8`
  для 12/15/18/21/24 слов, `MAX_WORD_REPEATS = 2`). Отказ
  блокирующий: `SeedError` с указанием нарушенного правила, кошелёк
  не открывается — до KDF.
- **R-5 (strict word-count gate).** Strict применим только к фразам с
  корректным числом слов wordlist'а (`SUPPORTED_WORD_COUNTS` =
  12/15/18/21/24); иное число слов — обычная ошибка strict-режима
  (parse error), а не отдельный вид отказа.
- **R-6 (entropy estimate warning).** Действует в обоих режимах и
  **не блокирует**. Для фразы считается оценка
  `bits = length * log2(|charset|)`, где `charset` — сумма мощностей
  классов символов, присутствующих во фразе:

  | Класс символов | Мощность |
  |---|---|
  | lowercase | 26 |
  | uppercase | 26 |
  | digits | 10 |
  | space | 1 |
  | прочие печатные символы | 33 |

  Если `bits < 128` — ПРЕДУПРЕЖДЕНИЕ: CLI выводит warning и продолжает
  работу; UI показывает предупреждение с возможностью продолжить.
  Использование НЕ препятствуется.
- **R-7 (деривация неизменна).** KDF хеширует фразу как есть (legacy
  path): permissive-режим не меняет ни одного байта деривации —
  существующие seed'ы (с passphrase и без) дают те же адреса.

#### Entropy floor (C6 — только strict)

Правила C6 действуют **только в strict-режиме** (R-4); в permissive
те же фразы принимаются (с warning по R-6 при `bits < 128`).

| Параметр | Значение | Обоснование |
|---|---|---|
| Минимум уникальных слов | `>= 4` из 12 / `>= 5` из 15 / `>= 6` из 18 / `>= 7` из 21 / `>= 8` из 24 | Грубая оценка: 12 уникальных слов из 2048 дают ~123 бит энтропии; 4 уникальных из 2048 дают ~44 бит — это ниже любого порога для seed с деньгами. |
| Максимум повторов одного слова | `<= 2` | BIP-39 разрешает дубликаты; для 24-словного seed `abandon` × 24 формально проходит BIP-39 check, но это явно не случайная последовательность. |
| Запрет obvious-patterns | `seed == a.repeat(N)` для `a ∈ wordlist`, `N >= word_count` | Повтор одного и того же слова seed-times — безусловный отказ. |

Error case (strict): не прошёл — `SeedError::InsufficientEntropy` с
указанием, какое правило нарушено (число уникальных / число повторов /
obvious-pattern).

Тесты:
- `test_seed_entropy_accepts_valid_bip39_12_words` — стандартный вектор (strict).
- `test_seed_entropy_rejects_all_duplicates` — `"abandon " * 12` отказ (strict).
- `test_seed_entropy_rejects_mostly_duplicates` — 11 × `abandon` + 1 × `legal` отказ (strict).
- `test_seed_entropy_rejects_repeated_phrase` — `"legal winner legal winner ..."` (2 уникальных) отказ (strict).
- `test_seed_permissive_accepts_arbitrary_phrase` — не-BIP-39 фраза проходит без strict (R-1).
- `test_seed_permissive_rejects_empty` — пустая фраза отклонена в обоих режимах (R-2).
- `test_seed_strict_rejects_wrong_word_count` — 13 слов → parse error strict-режима (R-5).
- `test_seed_entropy_estimate_warns_below_128_bits` — `bits < 128` → warning, приём продолжается (R-6).
- `test_seed_entropy_estimate_silent_at_or_above_128_bits` — `bits >= 128` → warning нет (R-6).

Wallet с пустым `passphrase` и валидным по BIP-39, но не проходящим
по entropy, мнемоником: в strict-режиме — **ошибка на этапе приёма
seed**, до KDF; кошелёк не открывается, пользователь видит «Entropy
too low — выберите другие слова». В permissive-режиме та же фраза
принимается (R-1; warning по R-6 при `bits < 128`).

### Зависимости в Rust core (`core/Cargo.toml`)

Версии указаны приблизительно на момент планирования (август 2026); фиксировать в `Cargo.toml` после проверки актуальных на crates.io.

**Crypto:**
- `k256` — pure-Rust secp256k1 (RustCrypto). Замена `secp256k1`/`secp256k1-sys`.
- `sha2` — SHA-256, SHA-512.
- `ripemd` — RIPEMD-160.
- `blake2` — BLAKE2b-256.
- `sha3` — Keccak-256 (legacy cascade использует его).
- `hmac` — HMAC-SHA512 (BIP-32 мастер + CKD').
- `pbkdf2` — PBKDF2-HMAC-SHA512 (BIP-39).
- `argon2` — Argon2id.
- `scrypt` — scrypt.

**Bitcoin protocol:**
- `bitcoin` — в production-коде только relay floor:
  `bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE` (решение C2);
  в тестах/fuzz (`fuzz_raw_tx`, psbt reference-проверки) — как
  независимый парсер/референс.
- `bip32` — BIP-32 derivation (общий leaf-walk `bip32_leaf` всех
  passphrase-KDF: pbkdf2/argon2id/scrypt).

**Encoding / data:**
- `serde` + `serde_json` — сериализация для API responses.
- `hex` — hex encoding/decoding.
- `base58` — base58-энкодер (декодер — собственный panic-free в
  `address.rs`, см. TODO.md про баг `base58-0.2.0`).

**Errors:**
- `thiserror` — typed errors (для нашего кода).
- `anyhow` — error context (для CLI верхнего уровня и тестов).

**Logging:**
- `tracing` — структурированный логгинг. CLI: stderr-subscriber через
  `cli/src/logging.rs` (`YUBTC_LOG`, решение C7; см. «CLI — команды →
  Logging policy»); Android-слой subscriber не инициализирует.

**Тесты (dev-dependencies):**
- `proptest` — property-based tests.
- `wiremock` или `mockall` — мокирование HTTP backend'ов.
- `tokio-test` — async test utilities.
- `criterion` — бенчмарки (опционально).

**Fuzzing:**
- `cargo-fuzz` — обёртка над libFuzzer. **Только `cargo-fuzz`** (не `bolero` — не интегрируются друг с другом).

**BIP-39 wordlist** — крейт `bip39` 2.0+ (RustCrypto; версия по
`Cargo.lock`), обёртка в `core/src/seed.rs`; wordlist на 2048 слов
встроен в крейт. Копия списка из
`yubtc-python/src/yubtc/seed.py:9-194` не используется.

### Python-зависимости (`pyproject.toml` yubtc-python)

- Уже есть `pbkdf2_hmac` через `hashlib`.
- Добавить `argon2-cffi` (или `passlib`) и `cryptography` (`scrypt` через `kdf.scrypt`).

### Файл-источник (`yubtc-python/src/yubtc/crypto.py`)

- `seed2bin` — основная KDF-функция (эта спека).
- `bin2privkey` — X25519-style clamp; применяется **только** к ветке
  `yubtc_cascade` (пустой passphrase) в **обоих** портах — Rust и
  Python. Для `pbkdf2`/`argon2id`/`scrypt` clamp пропускается: 32
  байта BIP-44 leaf идут в secp256k1 напрямую (см. свойство
  «`bin2privkey` clamp» выше). См. «Принятые решения», #1.
- `seed2privkey` — объединяет seed2bin + (кламп только для cascade) +
  `coincurve.PrivateKey(...)` / `k256::SigningKey`. Для unclamped-ветки
  выход KDF может теоретически оказаться ≥ n (p ≈ 2^-128) — Rust
  возвращает типизированную ошибку `InvalidScalar`.

### Тесты для совместимости Python ↔ Rust

Python-сторона (`yubtc-python/tests/test_crypto.py`):

- `test_seed2bin_empty_passphrase_matches_no_passphrase` — `seed2bin(seed, nonce, passphrase='')` ≡ `seed2bin(seed, nonce)` (обе — cascade).
- `test_seed2bin_passphrase_changes_output` — passphrase меняет ключ.
- `test_seed2bin_known_answers` / `test_seed2bin_passphrase_known_answers` — закреплённые KAT-векторы (cascade + passphrase).
- `test_seed2bin_kdf_known_answers` — закреплённые KAT-векторы для всех 4 KDF.
- `test_seed2bin_without_kdf_matches_explicit_default` — опущенный `kdf` даёт ту же ветку, что явное имя (auto-выбор по passphrase).
- `test_seed2bin_yubtc_kdf_rejects_passphrase` / `test_seed2bin_passphrase_kdfs_reject_empty_passphrase` — passphrase-правила веток.
- `test_default_kdf_matches_rust` — `default_kdf` зеркалит `KdfAlgo::default_for`.

Rust-сторона: `core/tests/kat_vectors.rs` прогоняет 16 референсных
векторов (`core/tests/kat/vectors.json`, все 4 KDF, полный пайплайн
`seed2bin` → ключ → адрес → WIF), сгенерированных `yubtc-python`
(`core/tests/kat/generate.py`).

### Rust API surface

| Модуль | Состав |
|---|---|
| `kdf.rs` / `privkey.rs` | Деривация по параметризованному пути (BIP-84/86) для `pbkdf2`-ветки; для не-BIP-32 KDF — вариант A (ОВ-2) либо `AddrTypeUnsupportedKdf`. |

## Адреса

yubtc работает **только на mainnet**. Testnet не поддерживается (out of scope).

### Base58check: P2PKH и P2SH

Версионные байты (base58check prefix → тип адреса):

| Prefix | Тип | Пример |
|---|---|---|
| `0x00` | mainnet P2PKH | `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` |
| `0x05` | mainnet P2SH  | `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy` |

`make_lock_script(addr)` декодирует base58check → version + hash160, выбирает scriptPubKey:
- P2PKH: `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`
- P2SH:  `OP_HASH160 <20-byte hash> OP_EQUAL`

Любой другой version byte (например, testnet `0x6f`/`0xc4`) → `InvalidAddress` (`AddressError::UnsupportedVersion` в Rust). Источник: `yubtc-python/src/yubtc/crypto.py` (`make_lock_script`), `yubtc-python/src/yubtc/fwd.py`.

В Rust port — собственный panic-free base58check в `address.rs`
(`decode_address`: длина 21, version `0x00`/`0x05`, иначе
`AddressError::UnsupportedVersion`); `bc1…`-адреса разбирает
`decode_segwit_address` (см. ниже).

### Bech32 / bech32m: P2WPKH и P2TR (BIP-173 / BIP-350)

Mainnet only, как и весь кошелёк. HRP — `bc` (testnet `tb` не поддерживается).

Совместимость: все легаси-ветки (P2PKH/P2SH, WIF, KDF, base58-адреса)
остаются bit-for-bit без изменений — существующие seed'ы дают те же
адреса (гвардируется существующими KAT из `core/tests/kat/vectors.json`).

**In scope:**

| Тип | BIP | Адрес | Подпись | Кодирование |
|---|---|---|---|---|
| P2WPKH | BIP-141 (валидация), BIP-143 (sighash) | `bc1q…` (witver 0, bech32) | ECDSA (RFC6979, low-S), SIGHASH_ALL | bech32, BIP-173 |
| P2TR (key-path only) | BIP-341 (sighash), BIP-86 (деривация), BIP-340 (Schnorr) | `bc1p…` (witver 1, bech32m) | Schnorr 64 байта, SIGHASH_DEFAULT (0x00) | bech32m, BIP-350 |

**Out of scope** (все — явные отказы, не «пока не работает»):

- ❌ P2WSH как форма личного адреса (witver 0, 32-байтная программа) — валидный bech32-адрес, но личный кошелёк его не создаёт и не тратит (`SegWitAddrError::UnsupportedProgram`); P2WSH-форма существует только как кворумная форма multisig (см. «Multi-sig»).
- ❌ P2SH-wrapped SegWit (BIP-141 nested, адреса `3…`) — двойное кодирование; нативная версия предпочтительна.
- ❌ Script-path spends в Taproot для личных адресов (Tapleaf, Tapscript, контрольные блоки) — только key-path; кворумная script-path-трата — см. «Multi-sig».
- ❌ Lightning Network — исключено полностью (решение 2026-09-02, см. «Отклонённые предложения»).
- ❌ Witness version ≥ 2: парсер отвергает с `SegWitAddrError::UnknownWitnessVersion` (кошелёк выпускает только v0/v1).

| Witver | Скрипт | Программа | Checksum const | Кодирование | Пример формы |
|---|---|---|---|---|---|
| 0 | P2WPKH | 20 байт (hash160(compressed pubkey)) | 1 | bech32 (BIP-173) | `bc1q…` (42 символа) |
| 1 | P2TR | 32 байта (x-only output key после TapTweak) | `0x2bc830a3` | bech32m (BIP-350) | `bc1p…` (62 символа) |

Правила (тестируемые):

- **Charset** — `qpzry9x8gf2tvdw0s3jn54khce6mua7l` (GF(2⁵), polymod по BIP-173). Энкодер всегда выдаёт lowercase.
- **Case:** декодер принимает все-lowercase и все-uppercase, **смешанный регистр — отказ** (`SegWitAddrError::MixedCase`; BIP-173 MUST).
- **Длина:** полная строка ≤ 90 символов (BIP-173); иначе `SegWitAddrError::TooLong`.
- **Структура:** `<hrp>` + `1` (сепаратор) + data-part (witver — 1 символ charset + программа в 5-битных группах) + 6 символов checksum. Отсутствие сепаратора / символ вне charset / некорректный padding → `SegWitAddrError::InvalidStructure` / `InvalidCharacter`.
- **Checksum:** пересчёт polymod с const = 1 (bech32, witver 0) или `0x2bc830a3` (bech32m, witver 1); несовпадение — `SegWitAddrError::InvalidChecksum`. Использование bech32-const для witver 1 (и наоборот) — отказ (BIP-350 rule 2).
- **Program length:** v0 — только 20 байт (P2WPKH); v0 + 32 байта (P2WSH-форма) распознаётся парсером, но отвергается как вне scope (`SegWitAddrError::UnsupportedProgram`); v1 — только 32; иначе `SegWitAddrError::InvalidProgramLength`.
- **TapTweak (BIP-86):** output key `Q = P + int(tagged_hash("TapTweak", x(P)))·G`, где `P` — внутренний ключ (x-only 32 байта), merkle root пуст (key-path only). Чётный паритет `Q` обязателен; невыполнимо — `AddressError` (p ≈ 2^-128, типизированная ошибка, как `InvalidScalar`).

Dispatch при разборе адреса получателя (замена плоской `decode_address`): строка начинается с `bc1`/`BC1` → bech32-путь (`decode_segwit_address`); иначе — существующий base58check-путь без изменений. Ошибки обеих веток — типизированные; строка с валидным base58check, но чужим version byte, остаётся `InvalidAddress`.

Error surface: `SegWitAddrError { InvalidCharacter, InvalidChecksum, MixedCase, TooLong, InvalidHrp, InvalidProgramLength, UnknownWitnessVersion, UnsupportedProgram, InvalidStructure }` — `thiserror`, без паник; fuzz-цель `fuzz_bech32` (см. «Тесты и quality gates» ниже и «Качество и CI»).

### Миграция и совместимость

- **Существующие кошельки работают без миграции:** тот же seed+passphrase+KDF+`--addr-type legacy` даёт те же адреса/WIF байт в байт; UTXO легаси-форм остаются видимы (scan всех форм) и тратятся без изменений. KAT-гвард в `vectors.json`.
- **Default-адрес получения** — P2WPKH; это единственное видимое отличие для пользователя без флагов. Критерий принятия: баланс/UTXO-набор не изменяется на тех же seed'ах при сохранении формы (E2E-сравнение scan-вывода).
- **Выбор типа:** CLI `--addr-type native|taproot|legacy` (default `native`); Android — настройка `AddrTypeSetting` (default `native`); UI/CLI-sketch: `yubtc address --addr-type taproot`, ReceiveScreen-переключатель. Смена типа меняет только адреса получения/cashback — не ключи (для `pbkdf2` ключи по BIP-84/86 независимы, для варианта A — та же кодировка).

### Тесты и quality gates (адреса и кодирование)

- **Coverage:** gate **lines=100 / branches=100** не ослабляется (каждая ветка `SegWitAddrError` — покрыта).
- **Fuzz:** цель `fuzz_bech32.rs` — произвольные байты → `decode_segwit_address` → отсутствие panic/overflow/OOM; ночной прогон 60 сек на цель (как остальные цели `fuzz.yml`; PR-smoke нет). `fuzz_wif`/`fuzz_raw_tx` — без изменений (сыграют расширенные парсеры).
- **Property (`proptest`, ≥1000 cases на инвариант):** encode↔decode round-trip bech32/bech32m (включая uppercase-нормализацию при декодировании).
- **Официальные векторы (table-driven fixtures):**
  - BIP-173 `valid.txt`/`invalid.txt` и BIP-350 `invalid.json` — парсер bech32/bech32m (вкл. mixed-case, длину, checksum-константы);
  - BIP-86 векторы TapTweak (output key для известных m/86'-ключей).
- **KAT/xcompat:** KAT-матрица расширяется осью `addr_type` (16 существующих строк не пересчитываются); новые векторы: segwit/taproot-адреса для (KDF × nonce × seed), TapTweak, sighash-дайджесты, witness-hex. CLI xcompat (`tests/test_cli_xcompat.py`) — `address --addr-type native|taproot|legacy` Rust-подпроцесс ↔ Python, одинаковые строки на тех же 4 (seed, passphrase, KDF)-кортежах.

### Python-зеркало (yubtc-python)

- `crypto.py` (или соседний модуль адресов): pure-Python bech32/bech32m encoder/decoder по BIP-173/350 reference; `pubkey2segwit_addr`, `pubkey2taproot_addr`, `decode_segwit_addr` — API-зеркало Rust.
- `transaction.py`: `bip143_sighash`, `taproot_keypath_sighash`, BIP-340 Schnorr (reference-алгоритм, детерминированный `aux_rand = 0x00×32`); witness-сериализация и txid/wtxid-расщепление зеркально.
- `wallet.py` / `fwd.py` / `cli.py`: `addr_type`-параметр, vsize-fee loop, dust-константы 294/330, `--addr-type`.
- **Bit-for-bit паритет обязателен** для: bech32/bech32m-строк, TapTweak output keys, BIP-143/BIP-341 digests, wire-hex смешанных (legacy+witness) транзакций. Проверка — CLI xcompat и KAT.

### WIF format

Экспорт приватного ключа (`yubtc dumpprivkey`) и импорт WIF — **только compressed, только mainnet**:

```
WIF = base58check(0x80 || <32-byte secret> || 0x01)
       └─────┬────┘ └──────┬───────┘ └────┬────┘
             │             │              └── compression flag (всегда 0x01)
             │             └── 32-байтный секрет (после yubtc_cascade; для pbkdf2/argon2id/scrypt clamp не применяется)
             └── mainnet version byte
```

Свойства:
- **Compressed only.** Uncompressed WIF (`0x80 || <32-byte>`, без trailing `0x01`) **не поддерживается** — все pubkey'и в yubtc compressed (secp256k1 всегда даёт 33-байтный compressed pubkey).
- **Mainnet only.** Version byte `0x80`. Testnet WIF (`0xef`) → `InvalidWIF`.
- **Round-trip:** `privwif2privkey(privkey2privwif(privkey)) == privkey` для любого валидного 32-байтного секрета в диапазоне secp256k1.
- **Checksum:** стандартный base58check (4 байта double-SHA256 в конце).

Error cases (Rust `WifError`):
- Wrong version byte (`!= 0x80`) → `WifError::UnsupportedVersion`.
- Wrong length (body не 33 байта с `0x01`-суффиксом) → `WifError::BadBodyLength`.
- Trailing byte `!= 0x01` → `WifError::Uncompressed` (uncompressed).
- Bad base58 / checksum → `WifError::Invalid`.
- Secret вне secp256k1 order → `PrivKeyError::InvalidScalar`.

Источник: `yubtc-python/src/yubtc/crypto.py` (`privkey2privwif`,
`privwif2privkey`).

В Rust port — собственный panic-free base58check в `address.rs`:
`privkey_to_wif` / `wif_to_secret` / `wif_to_privkey`, с ручной
валидацией compressed flag и mainnet version.

### Rust API surface

| Модуль | Состав |
|---|---|
| `address.rs` | Base58/P2PKH/P2SH/WIF-поверхность; `TWitnessProgram { version, program }`, `SegWitAddrError`, `pubkey_to_segwit_address`, `pubkey_to_taproot_address` (TapTweak внутри), `decode_segwit_address`; `redeem_to_p2sh_address(redeem) -> TAddress` — hash160 → `make_p2sh_lock_script` → base58check `0x05`; `redeem_to_p2wsh_address(redeem) -> TAddress` — SHA256 → witness v0/32 → bech32; `decode_p2wsh_address(addr) -> Result<[u8; 32]>` — строгий декодер `bc1q`-v0/32 (bech32-checksum); `redeem_to_tapscript_address(script) -> Result<TAddress>` — leaf_hash → tweak от NUMS `H` → bech32m v1; `decode_taproot_address(addr) -> Result<[u8; 32]>` — строгий декодер `bc1p`-v1/32 (bech32m-checksum). |
| `misc.rs` | `taproot_tweak_script_scalar(p, leaf_hash) -> Result<Scalar, AddressError>` — `int(tagged_hash("TapTweak", p ‖ h))` с проверкой `t ≥ n`; существующая `taproot_tweak_scalar` (BIP-86, пустой рут) — без изменений. |

### Закреплённые решения

Решения приняты и реализованы; нормативные формулировки — в правилах
разделов выше. Изменение решения — запись в `DEVIATIONS.md`.

- **ОВ-1 (default addr type).** Default — **`Native` (P2WPKH)**, P2TR — opt-in (`DEFAULT_ADDR_TYPE`, «Адресная политика и nonce→path mapping»); на P2TR default не переводится.
- **ОВ-2 (SegWit/Taproot для не-BIP-32 KDF).** Вариант A: тот же ключ, другая кодировка (см. «Адресная политика и nonce→path mapping», включая cross-type linkability); вариант B (`AddrTypeUnsupportedKdf`) отвергнут.

## Скрипты

### Lock-скрипты по форме адреса (`script.rs`)

- P2PKH: `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`.
- P2SH:  `OP_HASH160 <20-byte hash> OP_EQUAL`.
- `make_p2wpkh_lock_script(hash160: &[u8; 20]) -> [u8; 22]` — `OP_0 (0x00) OP_PUSHBYTES_20 (0x14) <20 байт>`.
- `make_p2tr_lock_script(output_key: &[u8; 32]) -> [u8; 34]` — `OP_1 (0x51) OP_PUSHBYTES_32 (0x20) <32 байта>`.
- `make_p2wsh_lock_script(sha256: &[u8; 32]) -> [u8; 34]` — `00 20 ‖ <32>` (для `bc1q`-v0/32 адресов кворумов).
- Симметричные экстракторы `extract_p2pkh_hash` / `extract_p2wpkh_hash` / `extract_p2tr_output_key` / `extract_p2wsh_program(script) -> Result<[u8; 32]>` (строгий shape-check `00 20 <32>`; как `extract_p2pkh_hash`, не общий декодер скриптов).
- `make_lock_script_for_address` строит скрипт по типу адреса получателя: base58 → P2PKH/P2SH (без изменений), `bc1` v0 → P2WPKH, `bc1` v0/32 → P2WSH, `bc1` v1 → P2TR.
- Существующие P2PKH/P2SH-функции и opcode-константы — без изменений.

### Multisig-скрипты (redeem / tapscript / witness)

- `OP_CHECKMULTISIG: u8 = 0xae`.
- `make_multisig_redeem_script(m, keys)` — валидация R-MS-2/3, sort (R-MS-4), каноническая сборка; `extract_multisig_quorum(script) -> (m, Vec<PubKey>)` — строгий shape-check; `ScriptError::InvalidMultisigRedeem`.
- `make_multisig_witness(redeem, sigs) -> Vec<Vec<u8>>` — P2WSH-раскладка `[‖, sigs…, redeem]` (BIP-141).
- `make_multisig_tapscript(m, keys: &[[u8; 32]])` (R-MS-7, sort R-MS-4 по x-only); `extract_multisig_tapscript(script) -> (m, Vec<[u8; 32]>)` (строгий shape-check); `ScriptError::InvalidMultisigTapscript`; `make_multisig_tapscript_witness(script, control_block, sig_slots)` (R-MS-11).

Нормативные layout'ы и правила сборки — «Multi-sig».

### Rust API surface

| Модуль | Состав |
|---|---|
| `script.rs` | `make_p2wpkh_lock_script`, `make_p2tr_lock_script`, `make_p2wsh_lock_script`, `extract_p2wpkh_hash`, `extract_p2tr_output_key`, `extract_p2wsh_program`; `OP_CHECKMULTISIG: u8 = 0xae`; `make_multisig_redeem_script(m, keys)` — валидация R-MS-2/3, sort (R-MS-4), каноническая сборка; `extract_multisig_quorum(script) -> (m, Vec<PubKey>)`; `make_multisig_witness(redeem, sigs)`; `make_multisig_tapscript(m, keys)`, `extract_multisig_tapscript`, `make_multisig_tapscript_witness`; `ScriptError::InvalidMultisigRedeem` / `ScriptError::InvalidMultisigTapscript`. |

## Транзакции и подписи

### Модель транзакции: witness и сериализация (`transaction.rs`)

- `TxIn` дополняется стеком witness: `pub witness: Vec<Vec<u8>>` (пустой для legacy-входов; обратная совместимость по умолчанию — все текущие конструкторы дают пустой стек).
- Сериализация разделяется:
  - `serialize_stripped()` — текущий layout (version ‖ vin ‖ vout ‖ locktime), witness игнорируется;
  - `serialize_wire()` — при наличии непустого witness у любого входа: version ‖ `0x00` (marker) ‖ `0x01` (flag) ‖ vin ‖ vout ‖ witness-стеки (varint-длина + элементы) ‖ locktime; иначе — байт в байт совпадает со `serialize_stripped()` (legacy-транзакции воспроизводятся как раньше).
- **txid не меняется семантически:** `id()` = dsha256(stripped) (BIP-141: witness не входит в txid); для legacy-транзакций совпадает с текущим `id()`. Новый `wtxid()` = dsha256(wire).
- `version` остаётся 2, `locktime` = `DEFAULT_LOCKTIME`, `sequence` = `SEQUENCE_RBF_SIGNALED` (`0xfffffffe`, BIP-125 RBF signal) — **без изменений для всех типов входов**.
- Подпись: `sign()` получает per-input схему из типа scriptPubKey входа (`SigScheme { Legacy, Bip143P2wpkh, Bip341KeyPath }`); смешанные транзакции (legacy + witness входы) допустимы, каждая схема считает свой digest.

### Signing — BIP-143 / BIP-341 key-path

**Общее:** `tagged_hash(t, m) = sha256(sha256(t) ‖ sha256(t) ‖ m)`.

**P2WPKH (BIP-143), SIGHASH_ALL (0x01):**

```
hashPrevouts = dsha256(concat(outpoint_i))            # 36 байт каждый
hashSequence = dsha256(concat(sequence_i))            # 4 LE каждый
hashOutputs  = dsha256(concat(serialize(out_i)))
preimage     = nVersion(4 LE) ‖ hashPrevouts ‖ hashSequence
             ‖ outpoint_i ‖ scriptCode_i ‖ amount_i(8 LE) ‖ nSequence_i(4 LE)
             ‖ hashOutputs ‖ nLockTime(4 LE) ‖ 0x01000000
sighash      = dsha256(preimage)
```

`scriptCode` P2WPKH = `0x19 0x76 0xa9 0x14 <20 байт> 0x88 0xac`. Witness-стек: `[DER-сигнатура ‖ 0x01, compressed pubkey (33)]`; `scriptSig` пуст. Сигнатура — детерминированная ECDSA (RFC6979, low-S) — меняется только digest.

**P2TR key-path (BIP-341), SIGHASH_DEFAULT (0x00):**

```
sha_prevouts      = sha256(concat(outpoint_i))        # plain SHA-256
sha_amounts       = sha256(concat(amount_i(8 LE)))
sha_scriptpubkeys = sha256(concat(compact_size(spk_i) ‖ spk_i))
sha_sequences     = sha256(concat(sequence_i(4 LE)))
sha_outputs       = sha256(concat(serialize(out_i)))
SigMsg = 0x00(hash_type) ‖ nVersion(4 LE) ‖ nLockTime(4 LE)
       ‖ sha_prevouts ‖ sha_amounts ‖ sha_scriptpubkeys ‖ sha_sequences
       ‖ sha_outputs ‖ 0x00(spend_type: ext_flag=0, annex нет) ‖ input_index(4 LE)
sighash = tagged_hash("TapSighash", 0x00(epoch) ‖ SigMsg)
```

- SIGHASH_DEFAULT = SIGHASH_ALL по покрытию; в witness **байт sighash не добавляется** (сигнатура ровно 64 байта). SIGHASH_ALL (0x01) для Taproot не используется.
- `hashTapLeaf = tagged_hash("TapLeaf", leaf_version ‖ compact_size(script) ‖ script)` существует только в script-path spends (см. «Дайджест — BIP-341 script-path» ниже) — в SigMsg key-path не входит (в key-path `ext_flag = 0`, extension-данных нет).
- Подпись — **BIP-340 Schnorr**, 64 байта `r ‖ s`. Ключ подписи — x-only внутреннего ключа (после деривации m/86' либо вариант A). `aux_rand` — детерминированный `0x00 × 32` в обоих портах (**ОВ-3**), KAT паритет.
- **Новый контракт данных:** BIP-341 требует amounts + scriptPubKeys **всех** входов — `SpendContext` (превью-метаданные из UTXO-списка) продевается в `sign()`; отсутствие — `TransactionError::MissingSpendContext`.

### Дайджест — BIP-341 script-path + расширение BIP-342

Дайджест script-path-траты tapscript-кворума — SIGHASH_DEFAULT (0x00),
закрепление ОВ-17. Общая схема BIP-341 key-path с `ext_flag = 1`;
annex отсутствует, `OP_CODESEPARATOR` в каноническом скрипте не
встречается:

```
sha_prevouts/sha_amounts/sha_scriptpubkeys/sha_sequences/sha_outputs — как в key-path
SigMsg  = 0x00 (hash_type: SIGHASH_DEFAULT) ‖ nVersion (4 LE) ‖ nLockTime (4 LE)
        ‖ sha_prevouts ‖ sha_amounts ‖ sha_scriptpubkeys ‖ sha_sequences
        ‖ sha_outputs ‖ 0x02 (spend_type: ext_flag=1, annex нет) ‖ input_index (4 LE)
ext     = leaf_hash (32) ‖ 0x00 (key_version) ‖ 0xFFFFFFFF (codesep_pos, 4 LE)
sighash = tagged_hash("TapSighash", 0x00 (epoch) ‖ SigMsg ‖ ext)
```

Подпись — BIP-340, ровно 64 байта `r ‖ s`; `aux_rand = 0x00 × 32`
(ОВ-3); подпись — секретом `d` без tweak (подписывается ключ, лежащий
в скрипте). Контекст кворумной траты — «Multi-sig → P2TR script-path».

### Тесты и quality gates (подписи и сериализация)

- **Coverage:** gate **lines=100 / branches=100** не ослабляется (каждая схема подписи — покрыта).
- **Property (`proptest`, ≥1000 cases на инвариант):** `total_size ≥ base_size`, `vsize ≥ base_size`, `weight = 3·base + total` — инвариант сериализации.
- **Официальные векторы (table-driven fixtures):**
  - BIP-143 официальный P2WPKH-пример — digest + witness-стек;
  - BIP-341 wallet test vectors (key-path, SIGHASH_DEFAULT) — sighash.
- **KAT/xcompat:** смешанная транзакция (legacy + P2WPKH + P2TR входы в одной tx) — фиксированный wire-hex на обоих портах.

### Rust API surface

| Модуль | Состав |
|---|---|
| `transaction.rs` | witness-стек в `TxIn`, `serialize_stripped`/`serialize_wire`, `wtxid`, `weight`, `vsize`, `SigScheme` (+ ветка `Bip341ScriptPath`: digest script-path — выше; подпись — BIP-340 секретом `d` без tweak, `aux_rand = 0x00×32`), `SpendContext`; `TransactionError` расширяется. Парсинг stripped-транзакции из поля `UNSIGNED_TX` PSBT — поверх существующих структур (`TxIn`/`TxOut`), witness в unsigned tx обязан быть пустым. |

### Закреплённые решения

Решения приняты и реализованы; нормативные формулировки — в правилах
разделов выше. Изменение решения — запись в `DEVIATIONS.md`.

- **ОВ-3 (BIP-340 `aux_rand`).** Детерминированный `0x00 × 32` в обоих портах (KAT-паритет, воспроизводимость подписи); при пересмотре — запись в `DEVIATIONS.md` с перекатыванием KAT.

## Кошелёк: UTXO-модель и scan

### UTXO data model

#### Идентификация UTXO

UTXO идентифицируется тройкой `(nonce, txid, vout)`, **не** `(address, txid, vout)`. `nonce` — индекс derivation address'а в gap-limit walk; address получается детерминированно из `(seed, nonce)` через KDF.

Это матчит Python: UTXO в `yubtc-python/src/yubtc/select.py` идентифицируется как `(pk.nonce, u['out_n'])`. Использование address'а как идентификатора избыточно (адрес derivable) и создаёт риск race conditions при gap-limit walk между scan'ом и build'ом.

#### Группировка по nonce

После scan'а UTXO группируются по nonce (и форме адреса). Единица
группы в Rust — `wallet.rs::Source { privkey: TPrivKey, unspent:
Vec<Utxo> }`: один `Source` — один `(nonce, форма)`, `privkey` несёт
и nonce, и форму (`addr_type`). FFI-слой (`uniffi_api.rs`) строит
такие группы из `(nonce, script_type)` выбранных UTXO, деривируя ключ
каждой группы из seed'а handle'а.

Это позволяет:
- Выбирать source по nonce (`send -n 5`).
- Итерировать в Coin Control picker'е.
- Cashback всегда возвращается на тот же nonce (last sourced или next gap).

#### Структура UTXO

```rust
pub struct Utxo {
    pub txid: [u8; 32],       // display-order dsha256
    pub vout: u32,
    pub amount: u64,          // satoshi
    pub script_pubkey: Vec<u8>,
    pub confirmations: u32,
}
```

`nonce` в `Utxo` не входит — он принадлежит обёртке: FFI-запись
`UtxoWithNonce { nonce, txid_hex, vout, amount_sat, confirmations,
script_type }` (см. «UniFFI export»).

#### SelectedSource (FFI record для Coin Control)

```rust
pub struct SelectedSource {
    pub nonce: u32,
    pub txid_hex: String,
    pub vout: u32,
}
```

UI хранит `Set<SelectedSource>` от Coin Control picker'а; build принимает эту коллекцию.

#### Валидация UTXO

| Правило | Ошибка (Rust) |
|---|---|
| `amount > 0` | `WalletError::UnsupportedAddress("zero amount UTXO")` |
| `txid` — 32 байта hex | `WalletError::UnsupportedAddress("bad txid hex: …")` |
| `script_pubkey` — канонический P2PKH/P2SH/P2WPKH/P2WSH/P2TR | `WalletError::UnsupportedUtxoScript` |
| `(nonce, txid, vout)` присутствует в переданном `utxos`-наборе | `YubtcError::Invalid` (make_transaction_multi: «not in utxos») |

`confirmations` и `vout` — `u32`, отрицательные значения
невозможны по типу; отдельной «future block» проверки нет. Проверки
выполняются в `Utxo::from_network` (`validate_utxo_script`) и на
границе FFI в `make_transaction_multi`.

Dust-пороги вынесены в хелпер `is_dust(amount, script)` (порог по
форме скрипта — см. «Fee loop и dust → Fee / witness accounting») и в
валидацию входящих UTXO не входят.

#### Cashback absorption (модель make_vout)

Отдельного интерактивного prompt'а абсорбции cashback нет (ни в CLI,
ни в Python, ни на Android — снято при аудите 2026-09-07). Absorption
зашит в `make_vout` как три ветки:

- **drain** (`amount = None`) — один выход на `dst` на `in_amount −
  fee`; cashback-выход не создаётся (cashback = 0).
- **exact match** (`amount + fee == in_amount`) — один выход на `dst`
  на запрошенную сумму; нулевой cashback абсорбируется в получателя.
- **standard send** — два выхода: `amount` на `dst`, cashback на
  `src` (last sourced / gap-limit address из scan'а).

Если cashback ниже dust-порога формы cashback-адреса, relay может
отклонить tx — пользователь выбирает сумму/fee сам; специальные
флаги (`--no-cashback-prompt`) не существуют.

#### Источник

`yubtc-python/src/yubtc/wallet.py` (`_select_inputs`, `_make_vin`, `_make_vout`), `yubtc-python/src/yubtc/misc.py` (`Unspent`), `yubtc-python/src/yubtc/fwd.py` (defaults).

### Scan strategies

yubtc поддерживает **два режима scan'а**, выбираемых caller'ом. Различие — Android (UI) vs CLI/Python (one-shot процесс).

#### `all_unspent(confirmations)` — eager (Android UI)

- Gap-limit walk до конца (нет early termination по target).
- Возвращает **все** UTXO со всех contributing addresses.
- Результат кэшируется в `WalletHandle`; cache invalidates на `set_backend` / `lock`.
- Используется Android UI для picker'а — нужно видеть всё, юзер выбирает вручную.
- Asymptotic: **O(K · R)** для первого вызова, **O(1)** для повторных (cache hit).

#### `select_inputs_until(target_sat, confirmations)` — lazy (CLI/Python parity)

- Walk'ает nonces с 0, fetch'ит `unspent(confirmations)` per-nonce.
- **Early termination:**
  - `cumulative_amount >= target_sat`, или
  - **gap-limit:** address никогда не получал funds AND не имеет UTXO (BIP-44 gap).
- Возвращает `SelectInputsResult { selected, utxos, cashback_addr }`:
  - `selected` — все UTXO всех contributing addresses как
    `Vec<SelectedSource>`;
  - `utxos` — тот же набор в форме `Vec<UtxoWithNonce>` (передаётся
    в `make_transaction_multi` без повторного fetch);
  - `cashback_addr` = last sourced address (target met) ИЛИ next gap-limit unused address (gap reached).
- Matches Python `_scan_inputs(target, confirmations)`.
- Результат скана не читается из кэша (каждый вызов — fresh network
  scan; найденное записывается в handle-кэш для последующих
  `all_unspent`).
- Asymptotic: **O(K' · R)** где K' ≤ K, early termination сокращает.

#### `default_selection(utxos, target_sat)` — pure greedy

- Pure function над pre-fetched `Vec<UtxoWithNonce>`, **no network**.
- Greedy: earliest nonce, smallest set meeting target.
- `target_sat = None` → все UTXO (drain mode).
- `target_sat = Some(N)` unreachable → все UTXO (insufficient).
- Empty utxos → `[]`.
- Matches Python `default_selection(sources, target)`.
- Используется Android auto-pick кнопкой в picker'е.
- Asymptotic: **O(U)** где U = количество UTXO.

#### `make_transaction_multi(utxos, selected, cashback_addr, dst, amount_sat, feekb_sat, fee_sat)` — build

- Pure function, **no network**.
- Caller передаёт pre-fetched utxos + selection + cashback target.
- Lookup `(nonce, txid, vout)` в хеш-таблице O(1).
- Validation: каждый `selected` должен быть в `utxos`; иначе `YubtcError::Invalid` («not in utxos»).
- Fee loop работает на validated selection.
- **Cashback_addr обязателен** (не implicit как было в `make_transaction`). Caller выбирает:
  - CLI: берёт из `select_inputs_until` возврата.
  - Android: VM вычисляет как last sourced address из `all_unspent` cache.

#### Data flow (Android)

```
unlock() → handle.allUnspent(6u)         # network: K · R
          ↓
   state.unspent: List<UtxoWithNonce>    # cache
          ↓
   user picks UTXO → state.selectedUtxos
        или
   user → "Auto-pick" → handle.defaultSelection(state.unspent, target)
                          → state.selectedUtxos
          ↓
   Build → handle.makeTransactionMulti(
       state.unspent,
       state.selectedUtxos,
       last_address,                     # cashback target
       dst, amount, feekb, fee_sat,
   )                                     # no network!
          ↓
   state.lastTx: TxResultRecord
          ↓
   Broadcast → handle.broadcast(txHex)   # network: 1 RTT
```

Network calls per session: **O(K + 1)** где K = gap-limit addresses, 1 = broadcast. Всё остальное — pure in-memory.

#### Data flow (CLI / Python parity)

```
send ADDR AMOUNT
  ↓
handle.selectInputsUntil(
    Some(AMOUNT + fee),
    confirmations=6,
)                                       # network: K' · R, early termination
  ↓
(selected_sources, cashback_addr)
  ↓
handle.makeTransactionMulti(
    unspent_from_scan,                  # same UTXO set returned from scan
    selected_sources,
    cashback_addr,
    ADDR, AMOUNT, feekb, fee_sat,
)                                       # no network
  ↓
txid, txhex
  ↓
broadcast(txhex)                        # network: 1 RTT
```

CLI при `send 0.001 BTC` с одним funded address = **2 RTT total** (1 scan + 1 broadcast).

#### Сводная таблица методов

| Метод | Network | Pure | Cacheable | Caller |
|---|---|---|---|---|
| `all_unspent(c)` | ✓ (K·R) | ✗ | ✓ (handle) | Android |
| `select_inputs_until(t, c)` | ✓ (K'·R) | ✗ | ✗ | CLI |
| `default_selection(u, t)` | ✗ | ✓ | n/a | Android auto-pick |
| `make_transaction_multi(u, s, c, ...)` | ✗ | ✓ | n/a | Оба |
| `broadcast(tx)` | ✓ (1 RTT) | ✗ | ✗ | Оба |

### Scan и cashback при нескольких формах адресов

- **Walk** (оба режима `all_unspent` / `select_inputs_until`) идёт по nonce, как сегодня, но на каждом nonce опрашивает **все три формы** (P2PKH + P2WPKH + P2TR; P2SH — только как получатель, своим кошельком не порождается). Стоимость: K·R → K·R·T, T ≤ 3; результаты кэшируются в `ScanCache` (eager-режим) как сегодня.
- **Gap-правило обобщается на nonce:** nonce «использован», если хотя бы одна форма имеет `n_tx > 0` или UTXO; walk останавливается на первом неиспользованном nonce. Early termination по target — как сегодня.
- **UTXO-валидация** (`validate_utxo_script` / `build_vin`): 25 байт P2PKH / 23 байта P2SH / 22 байта P2WPKH (`0x00 0x14 <20>`) / 34 байта P2WSH (`0x00 0x20 <32>`) / 34 байта P2TR (`0x51 0x20 <32>`); остальное — `UnsupportedUtxoScript`.
- **Cashback** — тот же `(nonce, форма)`, что у последнего источника («last sourced address»); не на тип `addr_type` кошелька. Dust-prompt использует пороги по форме cashback-скрипта (см. «Fee loop и dust»).
- **Идентификация UTXO не меняется:** `(nonce, txid, vout)`; форма адреса derivable из `script_pubkey`, в идентификатор не входит.

### Rust API surface

| Модуль | Состав |
|---|---|
| `wallet.rs` | `AddrType`, `TPrivKey::address_of(addr_type)`, ветки адреса/скрипта/UTXO-валидации/witness-подписи; fee loop на vsize; `is_dust` по всем формам скрипта. `scan`/`selector`/fee-loop-алгоритм структурно не меняются. |

### Закреплённые решения

Решения приняты и реализованы; нормативные формулировки — в правилах
разделов выше. Изменение решения — запись в `DEVIATIONS.md`.

- **ОВ-4 (стоимость multi-form scan).** Scan всех трёх форм всегда (T ≤ 3, кэш в `ScanCache`); batch-API бэкендов — отдельным вопросом.

## Fee loop и dust

### Fee loop algorithm

**Источник истины:** фактическая реализация в `yubtc-python/src/yubtc/wallet.py` (`_make_transaction` / `_pick_best_fee_loop_candidate`).

**Зачем:** при построении транзакции нужно одновременно удовлетворить три условия:
1. `fee ≥ MIN_RELAY_TX_FEE` (relay-policy Bitcoin Core: **1000 sat/kvB
   = 1 sat/vB**, константа `DEFAULT_MIN_RELAY_TX_FEE`). Не наша политика — это нижняя граница,
   ниже которой mempool tx не принимает. Читаем напрямую из
   `bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE` либо из fee-estimator'а Bitcoin
   Core; **не дублируем константу** в `fwd.rs` или в Python-референсе.
   Старое имя `MINIMAL_FEE = 2000 sat` плохо описывало суть и плохо
   взаимодействовало с feerate-циклом (фиксированное число sat
   конфликтует с feerate×size).
2. `fee / vsize ≥ feerate` (sat/vB) — пользовательский rate (default 1 sat/vB).
3. `inputs покрывают amount + fee`.

Прямой перебор `feerate * size / 1000` даёт классическую осцилляцию (±1 sat tolerance упирается в size-estimate drift). Решение yubtc-python — **один unified механизм** вместо трёх слоёв защит.

#### Алгоритм

```rust
// Упрощённый псевдокод; реальная сигнатура в yubtc-python/wallet.py:_pick_best_fee_loop_candidate
struct Candidate {
    fee: u64,            // satoshi fee = sum(in) - sum(out)
    size: usize,         // virtual size в байтах
    payload: TxPayload,  // vout_result + signed_tx
}

/// Phase 1: accumulate candidates from fee-loop iterations.
/// Multiple entries per size are KEPT (не перетираются) — финальный
/// picker делает best-pick глобально.
let mut by_size: BTreeMap<usize, Vec<(u64, TxPayload)>> = BTreeMap::new();
for cand in fee_loop_iterations() {
    by_size.entry(cand.size).or_default().push((cand.fee, cand.payload));
}

/// Phase 2: single-pass best-pick (как в Python).
/// Правило 1: fee >= size * feekb / 1000  AND
///            fee >= (size * MIN_RELAY_TX_FEE_SAT_PER_KVB) / 1000.
/// Правило 2 (приоритет): smallest size; tiebreak — smallest fee для
/// того же size (меньше overpay, та же feerate).
fn pick_best(by_size: &BTreeMap<usize, Vec<(u64, TxPayload)>>,
             feekb: u64, minimal_relay_fee_per_kb: u64) -> Option<TxPayload> {
    let mut best: Option<(usize, u64, TxPayload)> = None;
    for (size, entries) in by_size {
        for (fee, payload) in entries {
            let needed = (size as u64) * feekb / 1000;
            let relay_floor = (size as u64) * minimal_relay_fee_per_kb / 1000;
            if fee < needed || fee < relay_floor { continue; }
            let dominated = match best {
                None => true,
                Some((bs, bf, _)) => size < bs || (size == bs && fee < bf),
            };
            if dominated {
                best = Some((*size, *fee, payload.clone()));
            }
        }
    }
    best.map(|(_, _, p)| p)
}

/// Phase 3: fallback — если ни одна итерация не уплатила rate
/// (pathological feekb), берём smallest size ever produced.
/// "Pays some fee" > "relay rejected" — tx остаётся валидной.
fn pick_best_or_fallback(by_size: &BTreeMap<usize, Vec<(u64, TxPayload)>>
                        ) -> Option<TxPayload> {
    pick_best(by_size, feekb, minimal_relay_fee_per_kb)
        .or_else(|| by_size.keys().next()
            .and_then(|s| by_size[s].first().map(|(_, p)| p.clone())))
}
```

#### Свойства

- **Нет ±1 sat tolerance** — cycle detection на size-keyed map покрывает осцилляцию.
- **Нет iteration cap** — всегда сходится за один проход по candidates.
- **Нет max-fee rebuild** — candidates генерируются один раз (greedy selector), не пересобираются.
- **Deterministic** — для тех же UTXO всегда тот же candidate (порядок UTXO фиксирован).

#### Минимальные параметры

| Параметр | Значение | Источник |
|---|---|---|
| `DEFAULT_MIN_RELAY_TX_FEE` | `1000` sat/kvB (= 1 sat/vB) | Relay floor Bitcoin Core (`policy/policy.h`). Берётся из `bitcoin` crate (`bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE`) либо fee-estimator'а; **не дублируется** в `fwd.rs`. См. «Fee loop algorithm». |
| `DEFAULT_FEEKB` | 1000 sat/kB (1 sat/vB) | `core/src/fwd.rs` — отличается от yubtc-python (там `MINIMAL_FEE = 2000 sat` как default) |
| Size estimate | Из `bitcoin` crate (сжатые pubkey, low-S подписи) | library default |

#### Тесты

- `test_min_relay_tx_fee_constant_is_bitcoin_core_default` — константа floor'а равна Bitcoin Core default.
- `test_fee_loop_respects_min_relay_tx_fee` — candidate с fee ниже `size * MIN_RELAY_TX_FEE / 1000` отбрасывается, даже если size маленький.
- `test_fee_loop_picks_smallest_size` — из нескольких валидных выбирается с min size.
- `test_fee_loop_same_size_prefers_smaller_fee` — tie-break: меньший fee на том же size.
- `test_fee_loop_all_below_floor_falls_back_to_smallest_size` — fallback на наименьший size (pathological feerate).
- Drain-ветка (`amount=None` — все UTXO, fee из остатка) покрыта `make_vout`-тестами (`test_make_vout_drains_when_amount_is_none` и др. в Python; `make_vout_drain_branch` и proptest-инварианты fee loop в `wallet.rs`).
- Rust-сторона: `fee_loop_picker_*` / `wallet_make_transaction_fee_loop_picks_best` + proptest-инварианты vsize fee loop в `wallet.rs`.

### Fee / witness accounting (vbytes)

- **Единица fee loop — vbytes (vsize):** `weight = base_size·3 + total_size`, `vsize = ceil(weight / 4)` (BIP-141). `base_size` = stripped-сериализация, `total_size` = wire (с marker/flag/witness).
- Witness-дисконт: witness-байты весят ×1/4 (отсюда ~57.5 vB на P2WPKH-вход против ~148 байт legacy-входа).
- Fee loop (`pick_best_fee_loop_candidate`): ключ candidate-map — **vsize**; формулы сохраняют числовую форму: `needed = vsize·feekb / 1000`, `relay_floor = vsize·DEFAULT_MIN_RELAY_TX_FEE / 1000`. Источник relay floor не меняется (`bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE`, 1000 sat/kvB = 1 sat/vB). `--feekb`/`-k` — sat на 1000 **vbytes**; имя флага сохранено.
- **Совместимость:** для транзакций без witness `vsize == bytes`, результат fee loop байт в байт совпадает с расчётом по size (существующие кошельки платят те же fee).
- `announce_tx` печатает размер в байтах (wire) **и** vsize; дедупликация `seen_sizes` в цикле — по vsize.

Dust (`is_dust`, константы в `fwd.rs`): порог = ⌊dustRelayFee (3
sat/kvB) · (размер сериализованного выхода + размер тратящего входа в
vB) / 1000⌋ по формуле Bitcoin Core `GetDustThreshold` (тратящий вход:
witness-формы — 67 vB, legacy — 148 vB):

| Форма выхода | Размер выхода | Порог (константа `fwd.rs`) |
|---|---|---|
| P2PKH | 34 байта | **`DUST_THRESHOLD_P2PKH = 546`** |
| P2SH | 32 байта | **`DUST_THRESHOLD_P2SH = 540`** |
| P2WPKH | 8+1+22 = 31 байт | **`DUST_THRESHOLD_P2WPKH = 294`** |
| P2WSH | 8+1+34 = 43 байта | **`DUST_THRESHOLD_P2WSH = 330`** (⌊3 · (43 + 67)⌋ = 330) |
| P2TR | 8+1+34 = 43 байта | **`DUST_THRESHOLD_P2TR = 330`** |

Хелпер `is_dust` выбирает порог по форме скрипта cashback-выхода
(используется тестами/property-инвариантами; runtime-блокировок на
dust нет).

Смоук-тесты fee loop: `test_fee_loop_vsize_legacy_unchanged` (на
legacy-наборах `vsize == bytes` — числовое совпадение),
`test_fee_loop_witness_discount`; property: witness-дисконт fee
(fee(vsize) < fee(bytes) на witness-heavy tx при равных данных);
coverage: каждый dust-порог — покрыт (gate 100/100 не ослабляется).

## PSBT — BIP-174

Partially Signed Bitcoin Transaction (BIP-174) — транспортный
контейнер для обмена частичными подписями. Стоит на механике
witness-модели транзакции (`serialize_stripped`/`serialize_wire`),
схемах подписи `SigScheme` (legacy SIGHASH_ALL / BIP-143 / BIP-341
key-path), RFC6979/BIP-340-конвенциях и multi-form деривации — всё
переиспользуется как есть («Транзакции и подписи», «Ключи и seed»);
сам PSBT механику не меняет. Всё, что на цепи, байт-в-байт совпадает
с существующими потоками.

### Роли BIP-174 — матрица поддержки

| Роль | Поверхность yubtc | Статус |
|---|---|---|
| Creator | `psbt create` (Creator + Updater совмещены, как в типичном кошельке) | ✅ полный: unsigned tx + UTXO-поля всех входов |
| Signer | `psbt sign` | ✅ полный для P2PKH / P2WPKH / P2TR key-path; чужие входы пропускает без подписи (BIP-174 MUST) |
| Combiner | `psbt combine` | ✅ полный (merge без интерпретации скриптов; конфликт значений — детерминированный отказ, не произвольный выбор) |
| Finalizer | `psbt finalize` | ✅ полный для поддерживаемых форм |
| Extractor | `psbt extract` | ✅ полный |
| — | `psbt decode` | ➕ расширение yubtc (человекочитаемый дамп; не роль BIP-174) |

**In scope (поля, которые yubtc читает и пишет):** `PSBT_GLOBAL_UNSIGNED_TX = 0x00` и `PSBT_GLOBAL_VERSION = 0xFB` в global map; `NON_WITNESS_UTXO = 0x00`, `WITNESS_UTXO = 0x01`, `PARTIAL_SIG = 0x02`, `SIGHASH_TYPE = 0x03`, `REDEEM_SCRIPT = 0x04`, `WITNESS_SCRIPT = 0x05`, `FINAL_SCRIPTSIG = 0x07`, `FINAL_SCRIPTWITNESS = 0x08` в per-input map. Per-output map: определённых BIP-174 полей yubtc не пишет (реестр `0x00`–`0x02` не используется) — только preserve.

**Out of scope** (явные отказы, не «пока не работает»; парсер такие поля сохраняет как opaque-пары, см. «Сериализация»):

- ❌ PSBTv2 (BIP-370): поле версии `> 0` → `PsbtError::UnsupportedVersion` при парсинге; Creator пишет только v0 (`0xFB` отсутствует или `0x00`).
- ❌ BIP-32-деривация: `PSBT_GLOBAL_XPUB = 0x01`, `PSBT_IN/OUT_BIP32_DERIVATION = 0x06` — не пишем и не интерпретируем. Двойная причина: раскрытие деривационной структуры внешнему координатору и неприменимость к не-BIP-32 KDF (yubtc cascade/argon2id/scrypt путей в принципе не выражает) — см. ОВ-9.
- ❌ BIP-371 taproot-поля (`TAP_KEY_SIG = 0x13`, `TAP_SCRIPT_SIG =
  0x14`, `TAP_LEAF_SCRIPT = 0x15`, `TAP_BIP32_DERIVATION = 0x16`,
  `TAP_INTERNAL_KEY = 0x17`, `TAP_MERKLE_ROOT = 0x18` и taproot-поля
  per-output: `TAP_INTERNAL_KEY = 0x05`, `TAP_TREE = 0x06`,
  `TAP_BIP32_DERIVATION = 0x07`) — для личных key-path-трат script-path
  spends вне scope, key-path подписывается без них. (На пути
  P2TR-script-path-multisig поля `0x14`/`0x15`/`0x17` — W/R — см.
  «Multi-sig → PSBT: ветки форм».)
- ❌ Preimage-поля `PSBT_IN_RIPEMD160/SHA256/HASH160/HASH256 = 0x0a…0x0d` и `POR_COMMITMENT = 0x09` — preserve-only.
- ❌ Proprietary-поля `0xFC` всех трёх карт — preserve-only без разбора структуры (identifier/subtype не парсим); реестра proprietary-типов yubtc не ведёт.
- ❌ Подпись входов, требующих `REDEEM_SCRIPT`/`WITNESS_SCRIPT` вне канонических multisig-форм (P2SH, вкл. P2SH-wrapped SegWit; произвольные P2WSH-скрипты): поля сохраняются, Signer отвечает `PsbtError::UnsupportedInputScript`. Сами поля Creator личных транзакций не пишет — P2SH-входов у личного кошелька нет; канонические multisig-ветки — см. «Multi-sig».
- ❌ Sighash-флаги кроме закреплённых по форме (ANYONECANPAY/ANYALL и пр.) — ОВ-8.
- ❌ Файлы `.psbt` — только stdin/stdout (house rule `pushtx`).

### Сериализация

Grammar — BIP-174:

```
<psbt>    := 0x70 0x73 0x62 0x74 0xFF <global-map> <input-map>* <output-map>*
<map>     := <keypair>* 0x00
<keypair> := <keylen><keytype><keydata><valuelen><valuedata>
```

Правила (тестируемые):

- **Ключ:** `<keylen>` — compact size суммарной длины `<keytype>`+`<keydata>`; `<keytype>` — minimally-encoded compact size (неканоничное кодирование, например `0xFD 0x00 0x02` для типа 2, — отказ `PsbtError::NonMinimalCompactSize`); длина ключа ≥ 1 (ключ нулевой длины — терминатор карты; второй терминатор — `PsbtError::Truncated`). Для типов «No key data» keydata строго пуст (keylen = 1); `PARTIAL_SIG` требует pubkey 33 (compressed) или 65 байт в ключе — иная длина — `PsbtError::InvalidKeyLength` (вектор BIP-174 «invalid pubkey length»).
- **Значение:** ровно `<valuelen>` байт; `WITNESS_UTXO` и `NON_WITNESS_UTXO` должны парсироваться полностью, хвостовые байты — `PsbtError::InvalidFieldValue`.
- **Дубликаты:** повтор полного байтового ключа в одной карте — `PsbtError::DuplicateKey` (BIP-174: PSBT с дублями невалидна).
- **Лимиты:** суммарный размер входных байтов ≤ `PSBT_MAX_SIZE = 4 MiB` (константа `fwd.rs`; fuzz/OOM-гвард против allocation-bomb через 64-битный compact size); число input-/output-map ровно числу входов/выходов unsigned tx, иначе `PsbtError::MapCountMismatch`.
- **Unknown-field preservation:** поля вне таблицы ниже (включая известные по BIP, но неиспользуемые: `0x01`, `0x06`, `0x09`–`0x0d`, BIP-371, `0xFC`) хранятся как opaque-пары `(key_bytes, value_bytes)` и проходят весь пайплайн create→sign→combine→finalize→extract **байт-в-байт**: каждая пара переносится без изменения, wire-транзакция extractor'а их не видит. Гвард — property-тесты (см. «Тесты и quality gates»).
- **Каноническая форма:** сериализатор выдаёт пары каждой карты в порядке возрастания полных байтов ключа (тип, затем keydata, лексикографически) — детерминизм для bit-for-bit паритета с Python-зеркалом. Парсер принимает любой порядок. `serialize(parse(x)) == x` — для x в канонической форме; один проход канонизации стабилен (`serialize(parse(serialize(parse(x)))) == serialize(parse(x))`).
- **Транспорт:** base64 (RFC 4648 §4) — кодирование BIP-174; собственный panic-free кодировщик в `psbt.rs` (как bech32 — новых зависимостей нет; `base64`-feature крейта `bitcoin` не подключается).

Таблица полей. Доступ: **W** — пишет, **R** — читает типизированно, **P** — preserve-only (opaque-пара).

Global:

| Тип | Название | Доступ | Комментарий |
|---|---|---|---|
| `0x00` | UNSIGNED_TX | W/R | stripped-сериализация (см. «Транзакции и подписи»); scriptSig и witness всех входов пусты — заполненный scriptSig в unsigned tx — отказ (официальный вектор); пустой список выходов — отказ |
| `0xFB` | VERSION | W/R | u32 LE; читаем только `0`; не пишем вовсе (отсутствие = версия 0) |
| прочие | — | P | включая XPUB `0x01`, proprietary `0xFC` |

Per-input:

| Тип | Название | Доступ | Комментарий |
|---|---|---|---|
| `0x00` | NON_WITNESS_UTXO | W/R | полный prev-tx в wire-формате (может быть с witness); Creator пишет для P2PKH-входов (см. «Роли и wallet-потоки»); Signer перед подписью обязан сверить `dsha256(tx) == prevout.txid` |
| `0x01` | WITNESS_UTXO | W/R | TxOut: `amount (u64 LE) ‖ compact_size ‖ scriptPubKey`; Creator пишет для witness-входов; Signer сверяет `script_pubkey` с деривированным (см. «Валидация») |
| `0x02` | PARTIAL_SIG | W/R | ключ — pubkey (наш — всегда compressed 33); значение — DER-сигнатура + байт sighash `0x01` (legacy/P2WPKH) или ровно 64 байта Schnorr без sighash-байта (P2TR, SIGHASH_DEFAULT) — конвенции подписи («Транзакции и подписи») |
| `0x03` | SIGHASH_TYPE | R | u32 LE; не пишем; принимаем только совпадающий с закреплённым для формы входа (ОВ-8), иначе Signer молча не подписывает (BIP-174: signer, который не может подписать данным sighash, не добавляет подпись) |
| `0x04` | REDEEM_SCRIPT | P | подпись под P2SH вне multisig-форм не делаем (см. «Multi-sig») |
| `0x05` | WITNESS_SCRIPT | P | подпись под P2WSH вне multisig-форм не делаем (см. «Multi-sig») |
| `0x07` | FINAL_SCRIPTSIG | W/R | пишет Finalizer для legacy-входов; пустой scriptSig — поле НЕ ставится (BIP-174: unset вместо пустого массива) |
| `0x08` | FINAL_SCRIPTWITNESS | W/R | пишет Finalizer для witness-входов; сериализованный стек (`compact_size` числа элементов + элементы) |
| прочие | — | P | `0x06`, `0x09`–`0x0d`, BIP-371 `0x13`–`0x18`, proprietary, неизвестные |

Per-output: всё — **P** (включая `REDEEM_SCRIPT = 0x00`, `WITNESS_SCRIPT = 0x01`, `BIP32_DERIVATION = 0x02`).

### Роли и wallet-потоки

Подпись P2PKH/P2WPKH/P2TR — переиспользование схем подписи
(`SigScheme::from_script_pubkey`, BIP-143/341-дайджесты, RFC6979 low-S,
Schnorr `aux_rand = 0x00 × 32`); новое — контейнер и роутинг полей.
Потоки:

1. **«Подписать транзакцию внешнего координатора»** — `yubtc psbt sign`, полностью офлайн: все данные для подписи — в PSBT (свойство BIP-174, критично для stateless-кошелька: seed вводится один раз, сети не требуется).
2. **«Экспорт unsigned PSBT после Coin Control»** — `yubtc psbt create -i`: выбор UTXO в TUI → unsigned tx + UTXO-поля → base64 наружу. Selector и fee loop — те же методы, что у `send`.
3. **«Объединить две частичные подписи одного входа»** — `yubtc psbt combine` — база multisig-конвейера (см. «Multi-sig»): слияние подписей независимых подписантов.
4. **«Финализировать и разослать»** — `yubtc psbt finalize && yubtc psbt extract | yubtc pushtx` (extract отдаёт hex на stdin `pushtx` — pipe-совместимость).

**Creator (+Updater).** Шаги `send` (scan → selector → fee loop) без шага подписи: строится unsigned tx (cashback-выход — как в `send`), затем заполняются UTXO-поля: `WITNESS_UTXO` для witness-входов (amount — из scan-метаданных, `script_pubkey` — деривацией `(nonce, форма)`; форма — `script_type` из `UtxoWithNonce`), `NON_WITNESS_UTXO` для legacy-входов — для него нужен полный prev-tx: `NetworkBackend` дополняется методом `raw_transaction(txid) -> String` (hex; blockchain.info `/rawtx/<txid>?format=hex`, blockstream/mempool.space `/tx/<txid>/hex`, Mock — тривиально; сетевая цена `psbt create`: 1 scan + R raw-tx только при наличии P2PKH-входов). Изолированного Updater-метода нет — Creator пишет всё, что знает.

**Signer.** Ключевая новая логика — идентификация «своих» входов: PSBT не несёт nonce, а stateless-кошелёк не хранит соответствие UTXO→ключ. Signer идёт по nonce `0..PSBT_SIGN_MAX_NONCE` (константа `fwd.rs`; ОВ-9), для каждого nonce деривирует все три формы (как multi-form scan, но офлайн — только хеши) и сопоставляет с `script_pubkey` UTXO-поля входа; совпадение → `(nonce, форма)` → ключ и `SigScheme`. Вход без UTXO-поля — пропуск (подписать нечем); вход, чей скрипт не совпал ни с одной деривацией, — не наш, пропуск (BIP-174: signer не обязан подписывать всё и подписывает только то, что может). Пред-проверки подписи — «Валидация». Контракт BIP-174: Signer **только добавляет** данные — `PARTIAL_SIG` своих входов; всё остальное, включая unknown-пары, переносится как было.

**Combiner.** PSBT идентифицируются глобальным `UNSIGNED_TX` (байтовое равенство): различие — `PsbtError::ForeignTransaction`. Слияние: равный ключ с равным значением → одна пара; равный ключ с разным значением → `PsbtError::ConflictingField` — детерминированный отказ вместо разрешённого BIP-174 произвольного выбора (воспроизводимость/KAT; коммутативность на непересекающихся подписантах гарантирована). Разные ключи одного типа (например, два `PARTIAL_SIG` с разными pubkey) — обе пары сохраняются.

**Finalizer (per input).** Форма входа определяется по `script_pubkey` UTXO-поля (`SigScheme::from_script_pubkey`). Вход финализируем только когда форма завершена: P2PKH — есть `PARTIAL_SIG` → `FINAL_SCRIPTSIG = push(sig‖0x01) ‖ push(pubkey)`, `0x08` не ставится; P2WPKH — `FINAL_SCRIPTWITNESS = [sig‖0x01, pubkey]`, `0x07` не ставится; P2TR — `FINAL_SCRIPTWITNESS = [sig64]`. Сигнатура с байтом sighash, не совпадающим с `SIGHASH_TYPE` поля (если есть), блокирует финализацию входа (BIP-174 MUST). Вход с незавершённой формой остаётся нетронутым (финализатор работает per-input; полноту всей транзакции проверяет Extractor). После финализации входа промежуточные поля (`PARTIAL_SIG`, `SIGHASH_TYPE`, `REDEEM/WITNESS_SCRIPT`) удаляются; UTXO-поля и unknown-пары сохраняются (BIP-174 mandate: UTXO нужны Extractor'у для проверки итоговой tx).

**Extractor.** Все входы должны иметь завершённые финальные поля (`FINAL_SCRIPTSIG` для legacy, `FINAL_SCRIPTWITNESS` для witness) — иначе `PsbtError::NotFinalized`, PSBT не модифицируется. Итог — wire-сериализация (`serialize_wire`; marker/flag по наличию witness-стеков — см. «Транзакции и подписи»), hex на stdout.

### Валидация

Парсер (до любой роли): magic; структура карт и терминаторы; правила ключей/значений/дублей/лимитов (см. «Сериализация»); `UNSIGNED_TX` присутствует (v0-mandate), парсится, выходов ≥ 1; число карт совпадает с tx; версия 0.

Проверки Signer (обязательные по BIP-174 «Data Signers Check For», редакция yubtc):

- `NON_WITNESS_UTXO`: `dsha256(prev-tx) == prevout.txid` — иначе `PsbtError::UtxoMismatch`, подписи нет. Присутствует и для witness-входа — проверяется так же.
- `WITNESS_UTXO.script_pubkey` должен совпасть с деривированным скриптом `(nonce, форма)` (см. Signer выше) — иначе вход не наш; совпадение формы с «требующим redeem/witness script» (P2SH/P2WSH-скрипты) — `PsbtError::UnsupportedInputScript` (канонические multisig-формы — «Multi-sig»).
- Sighash: только закреплённые типы форм (ОВ-8); `SIGHASH_TYPE` с иным значением — вход пропускается без подписи.
- UTXO-поля отсутствуют у witness-входа — пропуск без подписи (BIP-143/341 требуют amount; данных нет).

Fee-sanity для отображения: `psbt sign` и `psbt decode` считают fee (Σ входов − Σ выходов) при наличии UTXO-полей всех входов и печатают; иначе warning (не ошибка — signer обязан работать только на данных PSBT).

Finalizer: финализация только завершённых форм (см. выше); сигнатуры с чужим sighash-байтом блокируют вход. Extractor: completeness-правило — «все входы завершены», иначе отказ без изменения PSBT.

### CLI

```
yubtc psbt create ADDR AMOUNT [-n NONCE] [-c CONFIRMATIONS] [-f FEE] [-k FEEKB] [-i]
             [--addr-type T] [--strict-bip39] [--provider NAME] [--retries N]
yubtc psbt sign [--strict-bip39]
yubtc psbt combine
yubtc psbt finalize
yubtc psbt extract
yubtc psbt decode
```

Все подкоманды читают PSBT (base64, одна строка; `combine` — ≥ 2 строк) со stdin и пишут результат в stdout: base64 (`create`/`sign`/`combine`/`finalize`), hex raw-tx (`extract`), человекочитаемый дамп + fee (`decode`). `create` — единственная команда с сетью (scan + raw-tx для legacy-входов); остальные офлайн. `-n` на `sign` нет — входы ищутся walk'ом по всем nonce (ОВ-9).

**Обоснование против альтернативы `send --psbt-export` (ОВ-6):** роли BIP-174 — отдельные шаги конвейера, флаг покрывал бы только Creator; `send` по контракту завершается готовой подписанной tx (или broadcast) — точка выхода другая; второй вход в ту же кодовую дорогу удваивает поверхность xcompat-тестов; подкоманды stdin→stdout композиционны в shell (`finalize && extract | pushtx`).

### Rust API surface

| Модуль | Состав |
|---|---|
| `psbt.rs` | `PartiallySignedTransaction { version, unsigned_tx: Transaction, inputs: Vec<PInput>, outputs: Vec<POutput>, unknown_global: Vec<UnknownKv> }`; `PInput { non_witness_utxo: Option<Transaction>, witness_utxo: Option<TxOut>, partial_sigs: Vec<(PubKey, Vec<u8>)>, sighash_type: Option<u32>, redeem_script/witness_script: Option<Vec<u8>>, final_scriptsig/final_scriptwitness: Option<Vec<u8>>, unknown: Vec<UnknownKv> }`; `UnknownKv { key: Vec<u8>, value: Vec<u8> }`. API: `parse(&[u8])`, `serialize() -> Vec<u8>` (канонизация), `from_base64`/`to_base64`, `create`, `sign_input`, `combine`, `finalize`, `extract_transaction`. Собственный base64 (RFC 4648), panic-free. Форма входа расширяется ветками P2SH/P2WSH/P2TR-multisig (резолв по паре `scriptPubKey` + `REDEEM_SCRIPT`/`WITNESS_SCRIPT`/tap-поля — см. «Multi-sig»); `CreateInput.redeem_script` / `CreateInput.witness_script` / `CreateInput.tap_leaf_script`; константы `T_IN_TAP_SCRIPT_SIG = 0x14`, `T_IN_TAP_LEAF_SCRIPT = 0x15`, `T_IN_TAP_INTERNAL_KEY = 0x17`, `T_IN_TAP_MERKLE_ROOT = 0x18` (типизированны на p2tr-пути; прочие формы — preserve). Парсер/сериализатор полей не меняются (`0x04`/`0x05` уже читаются и пишутся). |
| `psbt.rs` (errors) | `PsbtError { InvalidMagic, Truncated, NonMinimalCompactSize, InvalidKeyLength, DuplicateKey, UnsupportedVersion, MissingUnsignedTx, InvalidUnsignedTx, MapCountMismatch, InvalidFieldValue, UnsupportedInputScript, UtxoMismatch, UnsupportedSighashType, ConflictingField, ForeignTransaction, IncompleteInput, NotFinalized, TooLarge }` — `thiserror`, без паник; каждый вариант — ветка в coverage. |
| `net/` | + `raw_transaction(txid) -> String` в trait (4 реализации + Mock, см. «Роли и wallet-потоки»). |
| `wallet.rs` | + офлайн-хелпер переиспользования деривации `derive_script(nonce, form)` для walk'а Signer'а; scan/selector/fee loop — без изменений. |

**Без изменений:** все 4 KDF и seed policy, WIF, адреса/скрипты, `net/`-trait-структура (один новый метод), Coin Control selector, fee loop, `send`-флоу и его байт-в-байт результат, решение #10, no-`unwrap`/newtype-политики.

### Python-зеркало (yubtc-python)

- `psbt.py`: pure-stdlib (struct/hashlib/base64 stdlib) зеркало Rust-модуля: `Psbt`/`PsbtIn`/`PsbtOut`, `parse_psbt`, `serialize_psbt` (та же канонизация — сортировка по полным байтам ключа), `create_psbt`, `sign_psbt`, `combine_psbt`, `finalize_psbt`, `extract_transaction`, `to_base64`/`from_base64`. Ошибки — `PsbtError(Exception)` с теми же вариантами; kwargs-only, flake8 `--max-line-length=120`.
- Подпись — переиспользование `transaction.py` (BIP-143/341, Schnorr `aux_rand = 0x00 × 32`); walk по nonce — зеркально Rust.
- **Bit-for-bit паритет обязателен** для: base64 каждого этапа пайплайна (create → sign → combine → finalize → extract) на фиксированных (seed, passphrase, KDF)-кортежах; extracted wire-hex; поведение на unknown-полях (сохранение пар) и канонизация порядка; JSON-вывод `decode`. Проверка — CLI xcompat и KAT.
- **KAT:** `core/tests/kat/generate.py` расширяется осью PSBT → `core/tests/kat/psbt_vectors.json` (отдельный файл: векторы — объекты, не строки): для тех же 16 (seed, passphrase, KDF)-кортежей цепочка base64 (unsigned → signed → finalized) + extracted tx hex + вариант с инжектированными unknown-полями. Читается новым `core/tests/psbt_vectors.rs` (без subprocess, как `kat_vectors.rs`).
- Официальные векторы BIP-174 (valid/invalid из текста BIP) — table-driven fixtures в Rust-тестах: это векторы протокола, а не нашего пайплайна, поэтому в KAT не входят.
- **xcompat:** `yubtc-python/tests/test_psbt_xcompat.py` — Rust-CLI подпроцесс (`psbt create|sign|combine|finalize|extract|decode`) ↔ Python-функции на тех же кортежах: идентичный base64 каждого этапа. `create` — за существующим mock-гейтом `YUBTC_MOCK_BACKEND_URL` (+ mock `raw_transaction`), остальные этапы офлайн.

### Тесты и quality gates

- **Coverage:** gate **lines=100 / branches=100** не ослабляется (каждый вариант `PsbtError`, каждая роль, каждая форма финализации, каждая ветка walk'а — покрыты).
- **Официальные векторы BIP-174:** все valid-кейсы — parse → re-serialize → parse (стабильность) + применение применимых ролей; все invalid-кейсы («network transaction, not PSBT», «missing outputs», «filled scriptSig in unsigned tx», «duplicate keys», «invalid pubkey length», битые типовые ключи UTXO/redeem/witness/derivation) — конкретный вариант `PsbtError`, без паник.
- **Property (`proptest`, ≥ 1000 cases на инвариант):** unknown-field passthrough (инжекция произвольных пар во все три карты → полный пайплайн → пары байт-в-байт на месте, wire-tx не затронут); `combine(p, p) == p` (идемпотентность); коммутативность `combine(sign_A(p), sign_B(p)) == combine(sign_B(p), sign_A(p))` для непересекающихся подписантов (library-level, синтетические ключи, без wallet — база multisig-конвейера); `serialize(parse(x))` стабилен; parse произвольных байтов не паникует (дублирует fuzz-smoke).
- **Fuzz:** цель `fuzz_psbt.rs` — произвольные байты → `parse` (без panic/overflow/OOM; лимит `PSBT_MAX_SIZE`) + инвариант `parse(serialize(parse(x))) == parse(x)`; ночной прогон 60 сек на цель (как остальные цели `fuzz.yml`; PR-smoke нет).
- **Смоуки ролей (фиксированный seed):** E2E `create → sign → finalize → extract` = KAT wire-hex; отказ Extractor'а до finalize; конфликт `ConflictingField` на combine; подмена `WITNESS_UTXO` → `UtxoMismatch` без подписи.

### Закреплённые решения

Решения приняты и реализованы; нормативные формулировки — в правилах
разделов выше. Изменение решения — запись в `DEVIATIONS.md`.

- **ОВ-6 (форма CLI-поверхности).** Группа `yubtc psbt {create,sign,combine,finalize,extract,decode}` — роли 1:1 с конвейером BIP-174, stdin→stdout-фильтры композиционны (`extract | pushtx`); `send --psbt-export` и плоские команды верхнего уровня отвергнуты.
- **ОВ-7 (Android UI для PSBT).** FFI-only (`psbt_sign`/`psbt_extract`/`psbt_decode` на `WalletHandle`), Android-экранов нет; PSBT-UI (QR-транспорт, air-gap-сценарии) — отдельная экранная работа.
- **ОВ-8 (sighash на partial sig).** Pin по форме: P2PKH/P2WPKH — `SIGHASH_ALL` (0x01), P2TR key-path — `SIGHASH_DEFAULT` (0x00) — те же закрепления, что в «Транзакции и подписи»; поле `SIGHASH_TYPE` принимается только при совпадении с закреплённым, иначе вход не подписывается. Флаги ANYONECANPAY/ANYALL не поддерживаются; изменение политики — запись в `DEVIATIONS.md` + перекат KAT.
- **ОВ-9 (идентификация «своих» входов Signer'ом).** Bounded офлайн-walk по nonce (`PSBT_SIGN_MAX_NONCE = 1000` × 3 формы ≈ 3000 дериваций; вход за лимитом не подписывается, `psbt sign` печатает перечень неподписанных входов); BIP-32-пути (`0x06`/`0x01`) — preserve-only.

## Multi-sig

M-of-N мультиподпись: M подписей из N ключей. Кворум адресуется тремя
формами — `p2sh | p2wsh | p2tr` (параметр `--form` в CLI, `form` в
FFI/Python; в FFI — без дефолта, CLI-default `p2sh` —
задокументирован). Базовый скрипт кворума — bare
`OP_m … OP_n OP_CHECKMULTISIG` в redeem-скрипте (p2sh/p2wsh) либо
идиома `OP_CHECKSIGADD` в tapscript (p2tr; `OP_CHECKMULTISIG` в
tapscript отключён консенсусом BIP-342 — disabled-opcode, fail как
`OP_RETURN`). Трата идёт через полный
конвейер PSBT (BIP-174): роли `create → sign → combine → finalize →
extract` переиспользуются как есть; ECDSA-подпись — существующий
digest-commit путь (фикс `3f97d66`); дайджест и сериализация траты
зависят от формы (legacy `scriptSig` / BIP-141 witness-стек / BIP-341
script-path). Всё, что уже на цепи, не меняется: ни один байт
существующих потоков `send`/`psbt` личного кошелька не затрагивается.

### Scope

**In scope:** кворумные адреса и траты в трёх формах:

- **p2sh** — legacy-пространство адресов (base58check, P2SH `3…`):
  построение redeem-скрипта и адреса по (ключи, M); трата
  P2SH-multisig-входа через `scriptSig` без witness
  (P2SH-multisig-вход — legacy-вход, `vsize == bytes`);
- **p2wsh** — нативный SegWit: выход — canonical P2WSH
  `00 20 ‖ SHA256(redeem)` (34 байта), адрес — bech32 `bc1q…`
  witness-v0 с 32-байтной программой `SHA256(redeem)`; трата —
  witness-стек BIP-141;
- **p2tr script-path** (Tapscript, BIP-341/342, bech32m v1 `bc1p…`):
  leaf-скрипт версии `0xc0` с идиомой CHECKSIGADD (R-MS-7), дерево из
  **ровно одного** листа, внутренний ключ — NUMS-точка (R-MS-8,
  key-path траты невозможны по построению);

плюс трата через полный конвейер PSBT и подписание своего ключа в
чужом multisig-входе (`psbt sign`).

**Out of scope** (явные отказы, не «пока не работает»):

- ❌ P2SH-wrapped SegWit multisig (nested P2WSH) — вложенное
  кодирование отвергнуто (см. «Адреса»); multisig его не возвращает;
  вложенный P2SH-P2WSH и произвольные witness-скрипты остаются вне
  scope.
- ❌ Multi-leaf деревья и политики с ветвлением (у кворума один
  скрипт — Huffman-оптимизации не нужны).
- ❌ MuSig-агрегация ключей (3-round протокол — отдельная работа).
- ❌ Annex (`0x50`-элемент не пишем и не ожидаем); leaf-версии ≠
  `0xc0` и unknown key types; miniscript.
- ❌ Tapscript как получатель **личных** `send`/`psbt create`
  (guard CLI-слоя сохраняется — симметрично P2WSH: расширяется только
  кворумная поверхность `ms`).
- ❌ PSBT-поля multisig сверх нужного подписания: `BIP32_DERIVATION
  (0x06)` — preserve-only (ОВ-9), per-output `REDEEM/WITNESS_SCRIPT`
  — preserve-only; координационные протоколы (output descriptors,
  Electrum-обмен) не строятся — транспорт только base64-PSBT.

### Правила (тестируемые)

- **R-MS-1 (N и M — без дефолтов).** Ни одна multisig-операция не имеет
  значения по умолчанию ни для N (всего ключей), ни для M (порог
  подписей). Оба значения вводятся только явно: CLI — обязательные
  позиционные аргументы (`ms create N M`, `ms send … N M`); пропуск
  любого из двух — ошибка использования (не prompt-подстановка, не
  константа); FFI — обязательные параметры без `Option`; в `fwd.rs`
  дефолтов N/M нет. Пропущенный N или M — ошибка, никогда не значение.
- **R-MS-2 (границы кворума).** `1 ≤ M ≤ N ≤ 15`, иначе
  `MsError::QuorumBounds`. Верхняя граница 15, а не консенсусный
  `MAX_PUBKEYS_PER_MULTISIG = 20`: при N = 16 redeem-скрипт занимает
  34·16 + 4 = 548 > 520 байт (`MAX_SCRIPT_ELEMENT_SIZE` — консенсусный
  лимит на один push), такой P2SH-выход принципиально неистратим
  (redeem нельзя даже запушить в scriptSig). Лимит 20 ключей не
  достигается раньше 520-байтового.
- **R-MS-3 (только канонический bare CHECKMULTISIG).** Redeem-скрипт
  строится и принимается только в форме
  `OP_m ‖ (0x21 ‖ <33-байт compressed pubkey>)×N ‖ OP_n ‖ 0xae` —
  ничего кроме; дубликаты ключей отвергаются (create —
  `MsError::DuplicateKey`; чужой скрипт — `PsbtError::UnsupportedInputScript`:
  yubtc его не подписывает и не финализирует). Иная форма (в т.ч.
  uncompressed-ключи, OP_PUSHDATA-обёртки, составные скрипты) — отказ.
- **R-MS-4 (детерминированный порядок ключей — BIP-67).** `create`
  сортирует ключи лексикографически (по байтам compressed pubkey);
  один и тот же набор (N, M, ключи) даёт один и тот же адрес
  независимо от порядка аргументов CLI/FFI. Подписи в scriptSig
  выкладываются в порядке ключей redeem-скрипта (семантика
  CHECKMULTISIG); Finalizer берёт порядок из скрипта, а не из порядка
  поступления `PARTIAL_SIG`.
- **R-MS-5 (dummy-элемент — пустой push).** scriptSig всегда начинается
  с `OP_0` (один байт `0x00`) — компенсация известной off-by-one
  ошибки стека CHECKMULTISIG (POP лишнего элемента). После активации
  SegWit действует BIP-147 (NULLDUMMY): непустой dummy делает трату
  невалидной на консенсусе. Замечание о malleability: scriptSig входит
  в txid; пустой dummy и low-S-подписи делают трату yubtc канонической —
  исторический вектор третьесторонней пластичности txid через dummy
  (до BIP-147) закрыт самим BIP-147. (Для witness-формы p2wsh dummy —
  witness-элемент нулевой длины, отдельного `OP_0`-байта нет — см.
  «Формы кворума → P2WSH».)
- **R-MS-6 (свой ключ — только из seed).** Собственный ключ участника
  всегда деривируется из seed: legacy-форма на nonce `-n` (выбор —
  ОВ-10). WIF-аргумент принимается только для собственного ключа и
  только при совпадении секрета с деривированным на `-n` (иначе
  `MsError::ForeignWif`): секреты чужих ключей не принимаются и не
  хранятся (ОВ-11; кошелёк stateless).
- **R-MS-7 (канонический tapscript).** Leaf-скрипт строится и
  принимается только в форме

  `<pk_1> OP_CHECKSIG <pk_2> OP_CHECKSIGADD … <pk_N> OP_CHECKSIGADD
  <M> OP_NUMEQUAL`

  — идиом BIP-342 («Alternatives to CHECKMULTISIG»: перевод
  `m <pk_1> … <pk_n> n CHECKMULTISIG` в tapscript; он же `multi_a`
  в Miniscript). Байтовая раскладка: `<pk_i>` = `0x20 ‖ <32 байта
  x-only>` (33 байта — ключи в пуше всегда x-only, BIP-340/342);
  первый ключ закрывается `OP_CHECKSIG (0xac)` —
  его булев результат служит начальным значением счётчика; ключи
  `2..N` — `OP_CHECKSIGADD (0xba)`; финал — `OP_M` (`0x50 + M`) и
  `OP_NUMEQUAL (0x9d)` (не `NUMEQUALVERIFY` — зеркало plain
  `OP_CHECKMULTISIG`, не VERIFY-формы R-MS-3). Размер:
  `|s| = 33N + 1 + (N−1) + 1 + 1 = 34N + 2`. Семантика BIP-342:
  каждый сигнатурный опкод берёт ключ со стека и подпись под ним
  (непустая подпись с неверным ключом — мгновенный fail; пустая —
  пропуск, счётчик не растёт), `OP_NUMEQUAL` сравнивает счётчик с M.
  Дубликаты ключей, 33-байтовые compressed-ключи в пуше,
  OP_PUSHDATA-обёртки, `NUMEQUALVERIFY`, иной порядок опкодов, лишние
  байты — отказ (`ScriptError::InvalidMultisigTapscript` при extract;
  `PsbtError::UnsupportedInputScript` в Signer/Finalizer).
  CHECKMULTISIG-скрипт под P2TR консенсусом неистратим — смешанных
  форм «CHECKMULTISIG в tapscript» не существует.
- **R-MS-8 (внутренний ключ — NUMS; key-path не существует).** У
  кворума нет односигнатурной «эскейп-двери»: внутренний ключ дерева —
  константа `MS_TAPSCRIPT_INTERNAL_KEY` = x-only
  `50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`
  (`fwd.rs`) — NUMS-точка `H = lift_x(0x5092…ac0)`, приведённая прямо
  в тексте BIP-341 (X-координата = SHA-256 несжатой кодировки базовой
  точки G; дискретный логарифм неизвестен по построению — ОВ-15).
  Дерево — ровно один лист: меркл-рут совпадает с leaf-хешем,
  меркл-путь пуст, key-path-ветка отсутствует физически; даже
  гипотетическая key-path-трата по выходному ключу `Q = H + t·G`
  требовала бы dlog(H). yubtc не создаёт подписей под `Q` никогда.
- **R-MS-9 (границы формы p2tr — единые 15).** `1 ≤ M ≤ N ≤ 15`
  (R-MS-2) обязателен для **всех трёх форм**. Для P2WSH 520-байтовый
  лимит `MAX_SCRIPT_ELEMENT_SIZE` действительно неприменим —
  witness-скрипт не пушится через `scriptSig`, а исполняется как
  `witnessScript`, и консенсус допускает до 20 ключей; но один и тот
  же кортеж `(N, M, ключи)` обязан давать согласованный кворум в
  любой форме (форма — свойство *адреса*, не кворума).
  Формо-специфичные границы создали бы кворумы, существующие в одной
  форме и невоспроизводимые в другой (15-of-15 под P2WSH адрес,
  который нельзя перестроить как P2SH — «not spendable here, not
  rebuildable there»). В tapscript верхняя граница определяется тем же
  520-байтовым лимитом: tapscript исполняется как элемент initial
  stack, а BIP-342 сохраняет 520 байт на элемент
  (`MAX_SCRIPT_ELEMENT_SIZE`, «initial stack и push opcodes»), при том
  что 10000-байтовый лимит размера скрипта снят. Арифметика:
  `|s| = 34N + 2`; N = 15 → 512 ≤ 520 ✓; N = 16 → 546 > 520 ✗ —
  leaf-элемент 546 байт невалиден консенсусом. Совпадение не случайно
  и не подгонка: x-only-ключ короче compressed на байт (`0x20 ‖ 32`
  против `0x21 ‖ 33`), поэтому для идиомы BIP-342 консенсусный максимум
  ровно 15 — единая граница R-MS-2 совпадает с физическим пределом
  формы (лимит приходит из witness-элемента, не из scriptSig: в
  tapscript скрипт через scriptSig не пушится вовсе). Плотнее идиома
  BIP-342 не упаковывается: по одному сигнатурному опкоду на ключ
  обязателен, альтернативная инициализация `OP_0` + N×`CHECKSIGADD`
  даёт `34N + 3` — хуже. Единый `MS_MAX_PUBKEYS = 15` сохраняет
  cross-form инвариант и взаимно-однозначное соответствие адресов
  `3…` ↔ `bc1q…` ↔ `bc1p…` одного кворума; кворум 16+ не выражается
  ни в одной форме (p2sh — 548-байтовый redeem, p2tr — 546-байтовый
  leaf), т.е. «not spendable here» → «not rebuildable there» не
  возникает.
- **R-MS-10 (кодировка ключей — form-dependent).** BIP-340-верификация
  принимает x-only ключи, и именно 32-байтовые x-only ключи лежат в
  пуше tapscript. Кодировка аргументов привязана к форме: p2sh/p2wsh —
  compressed hex (66 hex-символов, префикс `02`/`03`, R-MS-3);
  **p2tr — x-only hex (64 hex-символа)**; смешение в одном вызове —
  `MsError::InvalidKeyEncoding`. BIP-67-сортировка (R-MS-4) для p2tr —
  лексикографическая по 32 байтам x-only (сортировка по compressed
  дала бы другой порядок; детерминизм «аргументы → адрес» сохраняется).
  Наш ключ — та же legacy-деривация на `-n` (ОВ-10, R-MS-6); в скрипт
  входит x-only = байты `1..33` compressed-ключа; подпись — Schnorr
  секретом `d`. **Tweak-скаляр key-path не применяется**: в script-path
  подписывается ключ, лежащий в скрипте (tweak — механика key-path,
  см. «Транзакции и подписи»). Следствие: участник P2SH-кворума с
  ECDSA-подписью (без BIP-340) не может косайнить tapscript-вход в
  принципе; паритет публичного ключа в x-only-кодировке не теряется —
  BIP-340 верифицирует и подписывает с нормализацией.
- **R-MS-11 (слоты подписей: обратный порядок, без dummy).** Итоговый
  witness (после M подписей): `[w_N, …, w_1]` ‖ tapscript ‖ control
  block, где `w_i` — слот ключа `pk_i`: 64-байтовая Schnorr-подпись
  (SIGHASH_DEFAULT, байт sighash не добавляется — ОВ-17) либо пустой
  вектор для не-подписантов. Порядок слотов **обратен** порядку ключей
  скрипта: стек при исполнении — `pk_i` сверху, счётчик под ним,
  подпись третьим (BIP-342), поэтому `w_1` обязан быть верхним
  элементом — BIP-342 фиксирует witness как `<w_n> … <w_1>`.
  Dummy-элемента нет (нет off-by-one — R-MS-5 неприменим). Ровно M
  слотов непусты и каждая подпись принадлежит своему ключу:
  «переподписывание» (все N слотов) даёт счётчик N ≠ M — невалидная
  трата; подпись в чужом слоте — мгновенный fail консенсуса.

### Модель участников и ключей

yubtc — single-seed кошелёк; участник кворума типа «мы» ровно один
(и тот опционален — watch-only-наблюдатель). Остальные N−1 участников —
косайнеры.

- **Наш ключ.** Деривируется из `(seed, passphrase, kdf)` на nonce
  `-n`: **legacy-ключ** — та же деривация, что `yubtc address -n X
  --addr-type legacy` / `dumpprivkey -n X` (для `pbkdf2` — путь
  `m/44'/0'/0'/0/n`; для не-BIP-32 KDF все формы делят один ключ —
  вариант А, ОВ-2). Мотивация: ключ multisig не имеет «адресной формы»
  на цепи — в redeem-скрипт входит только compressed pubkey, а подпись
  считается legacy-дайджестом; фиксируется та версия ключа, которая
  для всех KDF 1:1 видна в `dumpprivkey` (и проверяемо восстанавливается
  из seed). Выбор зафиксирован в ОВ-10. Для p2tr в tapscript входит
  x-only-проекция того же ключа (байты `1..33`; R-MS-10).
- **Ключи косайнеров.** Только compressed pubkey hex (66 hex-символов,
  префикс `02`/`03`); для p2tr — x-only hex (64 hex-символа, R-MS-10).
  WIF косайнера не принимается (R-MS-6): yubtc не
  хранит и не транспортирует чужие секреты; watch-only-импорт чужих
  WIF не поддерживается.
- **Наш ключ явно (CLI-sugar).** Вместо деривации `-n` свой ключ можно
  передать `--key <WIF>`: WIF обязан совпасть с деривированным на
  `-n` — команда вводит seed, сверяет и отвергает несовпадение
  `MsError::ForeignWif` (в т.ч. любой чужой WIF). Гарантия: в кворум
  попадает только ключ, который этот кошелёк способен деривировать
  заново и подписать. В FFI WIF не существует: ключи — только
  hex-pubkey'и, свой ключ подставляется из handle.
- **Watch-only create.** `ms create` без `-n`/WIF (все ключи —
  pubkeys) работает офлайн, без seed: адрес за кворумом получить
  можно, подписать — нет (`psbt sign` не найдёт свой ключ). Сценарий:
  получить адрес за чужим кворумом, тратить с другой машины.
- **Адрес.** Фиксирован кортежем (N, M, множество ключей) — ОВ-13:
  никакого scan/gap, адрес не входит в nonce-walk (multi-form scan его
  не видит; баланс — прямой запрос `get_unspent(address)`). Кодировка
  адреса — по форме: p2sh — `hash160(redeem)` → существующий
  `make_p2sh_lock_script` → base58check с version `0x05` → адрес `3…`
  (mainnet; эквивалент `privkey2addr` для скрипта); p2wsh/p2tr — см.
  «Формы кворума».

### Формы кворума: p2sh | p2wsh | p2tr

#### P2SH

Базовая форма кворума: legacy SIGHASH_ALL уже реализован (scriptCode —
параметр дайджеста), сериализация траты — `scriptSig` без
witness-механики, размерная модель — чистые байты.

**Дайджест** — legacy SIGHASH_ALL с `scriptCode = redeem` (тот же
алгоритм, что P2PKH, параметризованный scriptCode), sighash-байт
`0x01`.

Итоговая трата (после M подписей), layout scriptSig:

```
<scriptSig> := 0x00 ‖ push(sig_i ‖ 0x01)×M (в порядке ключей скрипта)
            ‖ push(redeem)
```

**Размерная модель fee loop (вход P2SH-multisig).**
`|scriptSig| = 1 + Σ(1 + |sig_i|) + pushlen(|redeem|)` (pushlen:
1 при длине ≤ 75, 2 — OP_PUSHDATA1 при ≤ 255, иначе 3 — OP_PUSHDATA2;
15-ключевой redeem (513 байт) идёт через OP_PUSHDATA2),
`vsize = 41 + |scriptSig|`
(legacy, witness-дисконта нет); dust cashback —
`DUST_THRESHOLD_P2SH = 540`.

**Сеть:** 1 запрос UTXO + R запросов `raw_transaction`.

#### P2WSH

**Кодирование.** Выход — canonical P2WSH `00 20 ‖ SHA256(redeem)`
(34 байта); адрес — bech32 `bc1q…` witness-v0 с 32-байтной программой
`SHA256(redeem)`.

**Witness-стек траты (финализированный layout, BIP-141).** В отличие
от P2SH-формы (R-MS-5: `OP_0`-байт в `scriptSig`), в witness-стеке
**отдельного `OP_0`-байта нет** — dummy-элемент это witness-item
нулевой длины (на проводе: CompactSize `0x00` без байтов данных),
который сам и есть пустой push, компенсирующий off-by-one ошибку
стека `OP_CHECKMULTISIG`. Точная раскладка (`M + 2` элемента):

```
<witness> := ‖ ‖ (пустая строка — CHECKMULTISIG dummy)
            ‖ push(sig_i ‖ 0x01)×M   (в порядке ключей скрипта, R-MS-4)
            ‖ ‖redeem‖               (witness script, последний элемент)
```

BIP-147 NULLDUMMY удовлетворён: dummy пуст; третий-element пустышки
не существует (историческая пластичность txid через dummy закрыта
самой witness-мутабельностью — witness не входит в txid).

**Дайджест — BIP-143, `scriptCode = redeem`.** Дайджест считается по
BIP-143 (SIGHASH_ALL, байт `0x01`, ОВ-8 pin); `scriptCode` —
**сериализация** witness-скрипта `CompactSize(|redeem|) ‖ redeem`
(как в P2WPKH-шаблоне `0x19 ‖ 25-байтовый скрипт`: CompactSize-префикс,
**не** OP_PUSHDATA-пуш), `amount` берётся из `WITNESS_UTXO`. Подпись —
тот же RFC6979 ECDSA-путь (digest-commit фикс `3f97d66`): BIP-143
sighash — ECDSA prehash.

**Размерная модель fee loop.** `scriptSig` пуст; размер — существующая
weight-модель (`base·3 + total`, `vsize = ⌈weight/4⌉`): sized-vin
fee loop несёт witness-стек с worst-case оценкой `MS_SIG_SIZE_ESTIMATE
= 73` на подпись — вес witness-секции входа: `CompactSize(M+2) +
[1] + Σᴹ(CompactSize(73) + 73) + CompactSize(|redeem|) + |redeem|`.
Dust cashback — `DUST_THRESHOLD_P2WSH = 330` sat: сериализованный
выход `8 + 1 + 34 = 43` байта, тратящий вход witness-формы 67 vB,
`⌊3 · (43 + 67)⌋ = 330` (та же формула Bitcoin Core
`GetDustThreshold`, что в «Fee loop и dust → Fee / witness
accounting»).

**Адресная поверхность core.** P2WSH разблокируется как форма
lock-скрипта и адреса кошелька: `make_lock_script_for_address` строит
`00 20 ‖ <32>` для `bc1q`-v0/32 адресов, `validate_utxo_script`
принимает 34-байтный P2WSH-шэйп (UTXO адреса кворума должен быть
представим — см. «Кошелёк: UTXO-модель и scan»), `is_dust` применяет
порог 330. Получатель личного `send`/`psbt create` **не меняется**:
typed-отказ («P2WSH addresses … are out of scope») сохраняется — guard
переносится на CLI-слой, чтобы разблокировка core-поверхности не
расширила документированный получатель личных переводов.

**Сеть:** 1 запрос UTXO и **0** `raw_transaction` (witness-форма,
BIP-143 коммитит amount; `NON_WITNESS_UTXO` и fetch prev-tx не нужны).

#### P2TR script-path (Tapscript)

Личные (не кворумные) P2TR-адреса остаются key-path BIP-86 (см.
«Адреса», «Транзакции и подписи») — script-path разблокируется только
на кворумной поверхности `ms`.

**Адрес и leaf-хеш (точные кодировки).**

```
leaf_hash = tagged_hash("TapLeaf", 0xc0 ‖ compact_size(|s|) ‖ s)   # один лист = меркл-рут
t         = int(tagged_hash("TapTweak", H ‖ leaf_hash))            # t ≥ n — отказ (≈2^-128, типизированная ошибка)
Q         = lift_x(H) + t·G
адрес     = bech32m(witver 1, x(Q)), HRP `bc` → `bc1p…` (62 символа)
c[0]      = 0xc0 | (y(Q) mod 2)                                    # версия листа + паритет Q
control_block (33 байта) = c[0] ‖ H                                # BIP-341: 33 + 32·depth, depth = 0
```

`tagged_hash(t, m) = sha256(sha256(t) ‖ sha256(t) ‖ m)` — см.
«Транзакции и подписи». Префикса `0x00` перед версией листа нет:
`hashTapLeaf` по BIP-341 — `leaf_version ‖ compact_size(size of
script) ‖ script`; `compact_size` — минимальное кодирование длины
(512 → `0xFD 0x00 0x02`), не OP_PUSHDATA-пуш. Паритет `y(Q)` попадает
в младший бит первого байта control block (`c[0] & 0xfe == 0xc0`,
`c[0] & 1 == y(Q) mod 2`).

**Трата (finalized witness, вход — witness-форма).**

```
<witness> := w_N ‖ … ‖ w_1 ‖ ‖s‖ ‖ control_block      (N + 2 элемента)
```

`scriptSig` пуст; сеть `ms send --form p2tr` — 1 UTXO-запрос и **0**
`raw_transaction` (симметрично P2WSH: `WITNESS_UTXO` коммитит amount).

**Дайджест** — «Транзакции и подписи → Дайджест — BIP-341
script-path + расширение BIP-342» (SIGHASH_DEFAULT, ОВ-17); подпись —
BIP-340 секретом `d` без tweak, `aux_rand = 0x00 × 32` (ОВ-3).

**Ресурсные лимиты BIP-342** не связывают каноническую трату:
sigop-budget = `50 + |witness serialized|`, каждая непустая подпись
стоит 50, а вносит в witness ≥ 65 байт: `|witness| = 1 + 65M + (N−M) +
(1 + |s|) + 34 = 64M + 35N + 38 ≥ 65M > 50M` — budget не исчерпывается
(«regular witnesses are unaffected», footnote BIP-342); лимит 1000
элементов стека и 520 байт на элемент — с запасом (R-MS-9).

**Размерная модель fee loop.** `scriptSig` пуст; witness-секция входа:
`1 + [M·(1+64) + (N−M)·1] + (1 + |s|) + (1 + 33)` байт; worst-case
оценка слота `MS_SIG_SIZE_ESTIMATE_TAP = 66` (CompactSize + 64-байтовая
подпись + байт sighash), канонический финал yubtc — 65. Пример 2-of-3:
`|s| = 104`, witness-секция 271 WU. Dust cashback — существующий
`DUST_THRESHOLD_P2TR = 330` (выход `51 20 ‖ <32>` — 43 байта,
тратящий вход 67 vB); **новых dust-констант не появляется**.

### PSBT: ветки форм (расширение конвейера BIP-174)

Multisig расширяет PSBT-конвейер формой multisig-входа; контейнер,
канонизация, unknown-passthrough, Combiner, ошибки — без изменений
(см. «PSBT — BIP-174»). `REDEEM_SCRIPT (0x04)` становится **W/R** на
пути P2SH-multisig, `WITNESS_SCRIPT (0x05)` — **W/R** на пути
P2WSH-multisig (preserve-only для прочих форм — уточнение таблиц
полей PSBT).

**P2SH-ветки.**

- **Creator (`ms send`).** `CreateInput` дополняется
  `redeem_script: Option<Vec<u8>>`: для P2SH-входа Creator пишет
  `NON_WITNESS_UTXO` (обязателен — вход legacy) и `REDEEM_SCRIPT
  (0x04)`.
- **Signer (`psbt sign`).** Вход с P2SH `scriptPubKey` больше не
  отвечает `UnsupportedInputScript` безусловно: при наличном
  `REDEEM_SCRIPT` он парсится по R-MS-3 (иначе — прежний отказ).
  Проверки BIP-174 «Data Signers Check»: `dsha256(NON_WITNESS_UTXO)
  == prevout.txid`; `hash160(redeem)` == hash в
  P2SH-скрипте UTXO-поля — иначе `PsbtError::UtxoMismatch`.
  Идентификация «своих»: walk по nonce `0..PSBT_SIGN_MAX_NONCE`
  (ОВ-9-паттерн) деривирует наши legacy-ключи; вход подписывается,
  если compressed pubkey деривированного ключа входит в список ключей
  redeem-скрипта — членство, а не совпадение `scriptPubKey` (P2SH-скрипт
  входа не «наш» по форме). Дайджест — legacy SIGHASH_ALL с
  `scriptCode = redeem` (тот же алгоритм, что P2PKH, параметризованный
  scriptCode), sighash-байт `0x01`; pin по духу ОВ-8: `SIGHASH_TYPE`
  иного значения — вход пропускается без подписи. `PARTIAL_SIG`
  добавляется только своим ключам; всё прочее переносится как было.
- **Finalizer (`psbt finalize`).** Новый путь `finalize_input`:
  P2SH-вход финализируем, когда `hash160(redeem)` сверён и в
  `PARTIAL_SIG` есть подписи всех M ключей скрипта (ровно по одной на
  ключ, pubkey ∈ список, sighash-байт `0x01`). Сборка в порядке ключей
  скрипта (R-MS-4): `FINAL_SCRIPTSIG = OP_0 ‖ push(sig‖0x01)×M ‖
  push(redeem)` (R-MS-5). Нет хотя бы одной подписи —
  `PsbtError::IncompleteInput` (вход нетронут; финализатор работает
  per-input). После финализации промежуточные поля (`PARTIAL_SIG`,
  `SIGHASH_TYPE`, `REDEEM_SCRIPT`) удаляются; UTXO-поля и unknown-пары
  сохраняются (BIP-174 mandate).
- **Extractor.** P2SH-вход требует `FINAL_SCRIPTSIG` (как legacy);
  witness-стек у P2SH-входа — `PsbtError::IncompleteInput`.
  Completeness-правило в целом — прежнее.

**P2WSH-ветки.**

- **Creator.** `CreateInput` дополняется `witness_script: Option<Vec<u8>>`:
  для P2WSH-входа Creator пишет `WITNESS_UTXO` (amount +
  `00 20 ‖ SHA256(redeem)`) и `WITNESS_SCRIPT (0x05)`. `NON_WITNESS_UTXO`
  и fetch prev-tx не нужны (witness-форма, BIP-143 коммитит amount):
  сеть `ms send --form p2wsh` — 1 UTXO-запрос и **0** `raw_transaction`
  запросов. Проверки Creator: redeem каноничен (R-MS-3), иначе
  `UnsupportedInputScript`; `SHA256(redeem)` == программа
  `scriptPubKey`, иначе `UtxoMismatch`.
- **Signer.** Вход с P2WSH `scriptPubKey` больше не отвечает
  `UnsupportedInputScript` безусловно: при наличном `WITNESS_SCRIPT`
  он парсится по R-MS-3 (иначе — прежний отказ). Проверки:
  `SHA256(redeem)` == программа scriptPubKey (иначе `UtxoMismatch`);
  членство compressed pubkey в ключах redeem-скрипта — членство, а не
  совпадение scriptPubKey (R-MS-4, симметрично P2SH); `SIGHASH_TYPE`
  ≠ 0x01 при наличном — вход пропускается (ОВ-8); наличный
  `NON_WITNESS_UTXO` обязан хэшироваться в prevout txid (BIP-174).
  Дайджест — BIP-143 с `scriptCode = redeem` (выше).
- **Finalizer.** P2WSH-вход финализируем, когда `SHA256(redeem)`
  сверен и в `PARTIAL_SIG` есть подписи всех M ключей скрипта (ровно
  по одной на членский ключ, sighash-байт `0x01`; лишние члены сверх
  порога детерминированно отсекаются с хвоста — как P2SH). Сборка в
  порядке ключей скрипта: `FINAL_SCRIPTWITNESS` = witness-стек
  раскладки выше (`M + 2` элементов). Нет хотя бы одной подписи —
  `PsbtError::IncompleteInput`. После финализации промежуточные поля
  (`PARTIAL_SIG`, `SIGHASH_TYPE`, `REDEEM/WITNESS_SCRIPT`)
  удаляются; UTXO-поля и unknown-пары сохраняются.
- **Extractor.** P2WSH-вход требует `FINAL_SCRIPTWITNESS` (стек
  декодируется в witness `vin`); `FINAL_SCRIPTSIG` на P2WSH-входе —
  `PsbtError::IncompleteInput` (симметрично отказу witness у
  P2SH-входа). Completeness-правило в целом — прежнее.

**P2TR-ветки (BIP-371).** Новые типизированные per-input поля
(на прочих формах — preserve-only, как в «PSBT — BIP-174»):

| Тип | Название | Доступ | Комментарий |
|---|---|---|---|
| `0x14` | TAP_SCRIPT_SIG | W/R | ключ: x-only pubkey (32) ‖ leaf_hash (32); значение: Schnorr-подпись — наши ровно 64 байта (ОВ-17) |
| `0x15` | TAP_LEAF_SCRIPT | W/R | ключ: control block (33 байта); значение: tapscript ‖ `0xc0`; Creator пишет для p2tr-входа |
| `0x16` | TAP_BIP32_DERIVATION | P | preserve-only; Signer игнорирует пути и leaf-hashes (ОВ-18) |
| `0x17` | TAP_INTERNAL_KEY | W/R | значение: NUMS `H` (32 байта); Creator пишет |
| `0x18` | TAP_MERKLE_ROOT | R | не пишем (рут = leaf_hash, вычислим из `0x15`); наличное сверяется, несовпадение — `UtxoMismatch` |

Per-output taproot-поля (`0x05`/`0x06`/`0x07`) — preserve-only
(без изменений).

- **Creator (`ms send --form p2tr`).** `CreateInput` дополняется
  `tap_leaf_script: Option<Vec<u8>>` (значение `0x15`: script ‖
  `0xc0`; control block ключа Creator строит сам — H, скрипт и паритет
  `Q` вычислимы офлайн). Пишет `WITNESS_UTXO` (`51 20 ‖ x(Q)`, amount
  из scan-метаданных адреса кворума), `TAP_LEAF_SCRIPT (0x15)`,
  `TAP_INTERNAL_KEY (0x17)`; `NON_WITNESS_UTXO`/`REDEEM_SCRIPT`/
  `WITNESS_SCRIPT` не пишет.
- **Signer (`psbt sign`).** Вход с P2TR `scriptPubKey` больше не
  исчерпывается key-path: при наличном `TAP_LEAF_SCRIPT` —
  script-path-ветка. Проверки: value парсится (последний байт ровно
  `0xc0`); keydata — 33 байта, `c[0] & 0xfe == 0xc0`, `c[1..33] == H`
  (иначе `UnsupportedInputScript`); скрипт каноничен (R-MS-7);
  `leaf_hash` → tweak → сверка `x(Q)` с программой `WITNESS_UTXO` и с
  наличным `TAP_MERKLE_ROOT` (иначе `UtxoMismatch`); членство x-only
  нашего ключа (walk по nonce `0..PSBT_SIGN_MAX_NONCE`, ОВ-9-паттерн)
  в ключах скрипта — членство, а не совпадение `scriptPubKey`;
  `SIGHASH_TYPE` только absent/`0x00` (ОВ-17). Частичная подпись —
  `TAP_SCRIPT_SIG` (ключ = наш x-only ‖ leaf_hash, значение 64 байта);
  всё прочее переносится как было.
- **Finalizer (`psbt finalize`).** P2TR-script-path-вход финализируем,
  когда сверка пройдена и в `TAP_SCRIPT_SIG` есть подписи всех M
  членских ключей (ровно по одной, 64 байта, pubkey ∈ скрипт).
  Сборка: `FINAL_SCRIPTWITNESS` = слоты R-MS-11 (`[w_N … w_1]`, пустые
  слоты не-подписантов) ‖ script ‖ control block (из keydata `0x15`).
  Нет хотя бы одной подписи — `PsbtError::IncompleteInput` (вход
  нетронут). После финализации промежуточные поля (`TAP_SCRIPT_SIG`,
  `TAP_LEAF_SCRIPT`, `TAP_INTERNAL_KEY`, `TAP_MERKLE_ROOT`,
  `SIGHASH_TYPE`) удаляются — mandate BIP-371 («finalizers should
  remove after `FINAL_SCRIPTWITNESS`»); UTXO-поля и unknown-пары
  сохраняются.
- **Extractor.** P2TR-script-path-вход требует `FINAL_SCRIPTWITNESS`;
  `FINAL_SCRIPTSIG` на таком входе — `IncompleteInput` (симметрично
  P2WSH). Completeness-правило в целом — прежнее.

### Поверхность

CLI — группа `ms`, зеркально `psbt` (паттерн ОВ-6):

```
yubtc ms create N M [--key HEX|WIF ...] [-n NONCE] [--form p2sh|p2wsh|p2tr]
yubtc ms send ADDR AMOUNT N M [--key HEX|WIF ...] [-n NONCE]
             [-c CONFIRMATIONS] [-f FEE] [-k FEEKB] [--provider NAME]
             [--form p2sh|p2wsh|p2tr]
```

- `ms create` — офлайн pure-функция: валидация R-MS-1…R-MS-4, сборка
  списка ключей (`--key` — повторяемый, + свой при `-n`; ровно N
  различных, иначе `MsError::KeyCountMismatch`), sort (R-MS-4), вывод
  в stdout: `m-of-n:`, `address:`, `redeem:` (hex). Seed запрашивается
  (stderr) только при `-n`/WIF. `ms create --form p2tr` дополнительно
  печатает `internal:` (NUMS) и `control:` (hex, 66 символов —
  33-байтовый control block). `redeem:`-строка для p2tr содержит
  **иной** скрипт, чем p2sh/p2wsh (CHECKSIGADD-идиома вместо
  CHECKMULTISIG): «один кворум — три адреса» означает одно множество
  ключей и (N, M), не одни байты скрипта; `redeem:`-строка p2sh и
  p2wsh идентична (один скрипт — два адреса).
- Флаг `--form`: default `p2sh` — задокументированное решение.
  R-MS-1 говорит о дефолтах N/M, а не формы; legacy-форма —
  консервативная форма кворума (совместимость существующих кворумов),
  поэтому отсутствие флага сохраняет прежнее поведение. Выбранная
  форма не подставляется молча в выводе: адрес (`3…` vs `bc1q…` vs
  `bc1p…`) и есть манифест формы.
- `ms send` — тонкая обёртка (ОВ-12) над существующими библиотечными
  этапами, без новой криптографии и сериализации: реконструкция
  кворума (аргументы `create`) → UTXO адреса кворума
  (`NetworkBackend::get_unspent`, фильтр `-c`; ОВ-13 — один адрес, без
  nonce-walk) → greedy-выбор входа (тот же принцип наименьшего
  префикса; все UTXO одного адреса — nonce-группировка не нужна) →
  fee loop → `PartiallySignedTransaction::create` (`NON_WITNESS_UTXO`
  через `raw_transaction`; + `REDEEM_SCRIPT`) → подпись своего ключа
  (partial sigs) → base64 в stdout (fee/warning — stderr). Наш ключ не
  входит в кворум (нет `-n`/WIF) — `MsError::NotAParticipant`: кошелёк
  строит траты только тех кворумов, в которых участвует. `--broadcast`
  нет: tx полна только после M подписей. Cashback — на адрес кворума,
  не на личный адрес (общие средства не должны уходить в единоличный
  контроль; следствие ОВ-13). Сеть: 1 запрос UTXO + R запросов
  `raw_transaction` (p2sh) / 0 (p2wsh/p2tr); scan кошелька не
  выполняется.
- **`ms sign` не вводится:** подпись своего ключа в multisig-входе —
  расширенный `psbt sign` (см. «PSBT: ветки форм»); отдельная команда
  не несёт новой семантики и дублирует кодовую дорогу (симметрично
  ОВ-6). Дальнейший конвейер — штатный PSBT: `psbt sign` (косайнеры) →
  `psbt combine` → `psbt finalize` → `psbt extract | yubtc pushtx`.
- **FFI.** `WalletHandle::ms_create_address` и `WalletHandle::ms_build_psbt`
  принимают обязательный параметр `form: MsFormName` (enum `P2sh |
  P2wsh | P2tr`, без дефолта — R-MS-1-дух); `MsAddressRecord.address`
  несёт адрес выбранной формы; для p2tr `MsAddressRecord.redeem_script_hex`
  несёт tapscript (имя поля не меняется — биндинги стабильны).
  `ms_unspent` не меняется (адрес — строка). Kotlin-биндинги
  регенерируются (uniffi-bindgen 0.32.0). Полный перечень FFI —
  «Принято (2026-09-02): полный surface» ниже.
- **Android.** `MsCreateScreen`/`MsSendScreen` — селектор формы
  (сегментированный выбор `p2sh`/`p2wsh`/`p2tr`, default `p2sh`);
  выбор проходит через ViewModel-мутации в FFI; JVM-тесты — паритет
  `MsQuorum`-хелпера для всех форм (ОВ-19). Контракты экранов —
  «Принято (2026-09-02): полный surface» ниже; детальные спеки —
  `specs/UI.md`.

### Python-зеркало (yubtc-python)

- `script.py`: `make_multisig_redeem_script`,
  `extract_multisig_quorum`,
  `redeem2p2sh_addr` — kwargs-only, flake8 `--max-line-length=120`,
  бит-в-бит то же кодирование (sort, layout, адрес); P2WSH-форма:
  `make_multisig_witness`-раскладка; p2tr-форма:
  `make_multisig_tapscript`, `extract_multisig_tapscript`,
  `tapscript_leaf_hash`, `tapscript_control_block`,
  `redeem2taproot_addr`.
- `psbt.py`: зеркальные P2SH/P2WSH-ветки Creator/Signer/Finalizer
  (`create_psbt`, `sign_psbt`, `finalize_psbt` принимают redeem);
  дайджест — legacy sighash с `script_code = redeem` в
  `transaction.py`; p2tr-ветки полей `0x14`/`0x15`/`0x17`;
  `transaction.py`: `tapscript_sighash` (SigMsg + ext), BIP-340.
- `wallet.py`: `ms_create_address`, `create_multisig_psbt` — зеркала
  wallet.rs; `form='p2sh'|'p2wsh'|'p2tr'` (kwargs-only, flake8
  `--max-line-length=120`, обязательный kwarg).
- **Bit-for-bit паритет обязателен** для: redeem-hex, адресов
  `3…`/`bc1q…`/`bc1p…`, base64 каждого этапа цепочки (unsigned →
  подписи двух участников → combined → finalized), итогового
  scriptSig/witness-стека и wire-hex — всех трёх форм. Проверка —
  CLI xcompat и KAT.
- **KAT:** `core/tests/kat/generate.py` расширяется осью multisig →
  `core/tests/kat/ms_vectors.json`: для тех же 16 (seed, passphrase,
  KDF)-кортежей — вывод `ms create` (адрес + redeem) при фиксированных
  синтетических ключах косайнеров и 2-of-3-цепочка с частичными
  подписями; P2WSH-вариант — 16 P2WSH-строк тех же (seed,
  own_nonce)-кортежей (prev tx платит на `bc1q…`-адрес кворума; те же
  суммы и получатель); p2tr-вариант — 16 строк 2-of-3 тех же кортежей
  (prev tx платит на `bc1p…`-адрес кворума): адрес, redeem, internal,
  control, base64 цепочки (unsigned → подписи двух участников →
  combined → finalized), итоговый witness-стек и wire-hex — рядом с
  существующими строками; существующие строки **не пересчитываются**
  (regression-гвард).
- **xcompat:** `yubtc-python/tests/test_ms_xcompat.py` — Rust-CLI
  (`ms create`, цепочка `psbt sign/combine/finalize/extract`; P2WSH:
  `ms create --form p2wsh`; p2tr: `ms create --form p2tr` + цепочка
  psbt-этапов) ↔ Python-функции на тех же кортежах: идентичные
  hex/base64. Сетевые шаги `ms send` — за mock-гейтом
  `YUBTC_MOCK_BACKEND_URL` (+ mock `raw_transaction`), как PSBT-этапы.

### Валидация (сводно)

| Проверка | Отказ |
|---|---|
| N или M не введены (CLI/FFI) | usage-ошибка / required-параметр (R-MS-1) |
| `1 ≤ M ≤ N ≤ 15` нарушено (любая форма — R-MS-2/R-MS-9) | `MsError::QuorumBounds` |
| число различных ключей ≠ N | `MsError::KeyCountMismatch` |
| дубликат ключа | `MsError::DuplicateKey` / `PsbtError::UnsupportedInputScript` |
| ключ не x-only hex (64) при form p2tr / не compressed (66) при p2sh/p2wsh | `MsError::InvalidKeyEncoding` |
| WIF ≠ деривированному на `-n` | `MsError::ForeignWif` |
| наш ключ не в кворуме (`ms send`) | `MsError::NotAParticipant` |
| redeem ≠ канонической формы (R-MS-3) | `ScriptError::InvalidMultisigRedeem` / `PsbtError::UnsupportedInputScript` |
| tapscript ≠ канонической формы (R-MS-7) | `ScriptError::InvalidMultisigTapscript` / `PsbtError::UnsupportedInputScript` |
| control block ≠ 33 байта / `c[0]&0xfe ≠ 0xc0` / внутренний ключ ≠ NUMS | `PsbtError::UnsupportedInputScript` |
| `hash160(redeem) ≠` hash в P2SH UTXO | `PsbtError::UtxoMismatch` |
| `SHA256(redeem) ≠` программа в P2WSH UTXO | `PsbtError::UtxoMismatch` |
| `x(Q) ≠` программа в P2TR UTXO; `TAP_MERKLE_ROOT ≠ leaf_hash` | `PsbtError::UtxoMismatch` |
| `WITNESS_SCRIPT` отсутствует / неканонический redeem (P2WSH-вход) | `PsbtError::UnsupportedInputScript` |
| `SIGHASH_TYPE ≠ 0x01` при наличном (p2sh/p2wsh) | вход пропускается (Signer) / `IncompleteInput` (Finalizer) |
| `SIGHASH_TYPE ∉ {absent, 0x00}` (p2tr); подпись `0x14` ≠ 64 байта | вход пропускается (Signer) / `IncompleteInput` (Finalizer) |
| < M подписей при финализации (любая форма) | `PsbtError::IncompleteInput` |
| `FINAL_SCRIPTSIG` на witness-входе (P2WSH/P2TR script-path, Extractor) | `PsbtError::IncompleteInput` |

### Rust API surface

| Модуль | Состав |
|---|---|
| `wallet.rs` | `ms_create_address(n, m, keys, own_nonce: Option<TNonce>) -> (TAddress, Vec<u8>)`; `ms_create_psbt(...)`, `ms_build_psbt_from_selected(...)` — Creator-оркестрация `ms send` (все принимают обязательный параметр `form`: адрес и lock-скрипт кворума, sized-vin fee loop — scriptSig-байты для P2SH / witness-стек для P2WSH / p2tr-ветка: адрес `bc1p…`, Creator: `WITNESS_UTXO` + `0x15`/`0x17`, walk-членство по x-only); `MsForm { P2sh, P2wsh, P2tr }`; `sign_psbt_with` — walk дополняется проверкой членства pubkey в redeem-скрипте; `MsError { QuorumBounds, KeyCountMismatch, DuplicateKey, ForeignWif, NotAParticipant, InvalidKeyEncoding }` (`thiserror`), маппинг в `YubtcError` — как `TransactionError`. |

### Принято (2026-09-02): полный surface (ОВ-14 — CLI + FFI + Android UI)

Решение владельца: **полный surface — CLI + FFI + Android
UI** — вместо FFI-only (транспорт PSBT всё равно нужен экранно,
делать его дважды нет смысла). Уровень фиксации — state-контракт и
переходы, не пиксельный; детальные спеки экранов — `specs/UI.md`.

**FFI surface — перечень дополнений `uniffi_api.rs`.** Новые:

- `WalletHandle::ms_create_address(n: u32, m: u32, keys: Vec<String>,
  nonce: Option<u32>) -> MsAddressRecord { address, redeem_script_hex }`
  — n/m обязательны (R-MS-1); `nonce = None` → наш ключ не участвует
  (watch-only create); WIF через границу не проходит (R-MS-6).
- `WalletHandle::ms_unspent(address: String, confirmations: u32) ->
  Vec<UtxoWithNonce>` — прямой `NetworkBackend::get_unspent` адреса
  кворума (ОВ-13): nonce-walk `all_unspent` кворумный адрес не видит;
  источник UTXO для `MsSendScreen`.
- `WalletHandle::ms_build_psbt(dst: String, amount_sat: u64, n: u32,
  m: u32, keys: Vec<String>, nonce: Option<u32>, utxos:
  Vec<UtxoWithNonce>, selected: Vec<SelectedSource>, feekb_sat: u64,
  fee_sat: u64) -> MsPsbtRecord { psbt_b64, fee_sat }` —
  Creator-оркестрация `ms send` (ОВ-12; библиотечный
  `wallet.rs::ms_create_psbt`) в форме `make_transaction_multi`:
  полный UTXO-набор + выбранное подмножество (решение #12, Coin
  Control); подпись своего ключа включена — результат уже несёт наши
  partial sigs.

Переиспользуются без изменений: `psbt_sign` (Signer-ветка multisig),
`psbt_decode` → `PsbtSummaryRecord` (decode/summary излучённого и
импортированного PSBT), `psbt_extract` + `broadcast` (импорт
finalized PSBT → wire-hex → txid).

**`MsCreateScreen`** (route `ms_create`; ViewModel-мутация
`msCreateAddress`, результат в `state.msAddress: MsAddressRecord?`).

- Inputs: `N` и `M` — обязательные поля без значений по умолчанию
  (R-MS-1): build-кнопка недоступна, пока оба не введены; клиентская
  проверка `1 ≤ M ≤ N ≤ 15` (R-MS-2), авторитетный отказ —
  `MsError::QuorumBounds` из FFI.
- Редактор списка ключей: ровно N compressed hex-pubkey'ей
  (66 hex-символов, префикс `02`/`03` — R-MS-3; для p2tr — x-only 64
  hex, R-MS-10); per-key валидация
  при вводе, дубликаты подсвечиваются и блокируют build
  (`MsError::DuplicateKey`); add/remove рядов, расхождение числа
  ключей с N отсекается FFI (`MsError::KeyCountMismatch`).
- Toggle «Наш ключ в кворуме» через nonce (R-MS-6, ОВ-10): выключен —
  watch-only create (полностью офлайн, seed не запрашивается);
  включён — доступно поле nonce, ключ деривируется на `-n` (seed —
  системный prompt, как в остальных потоках).
- Result state: адрес `3…` (p2sh) / `bc1q…` (p2wsh) / `bc1p…` (p2tr),
  redeem-скрипт hex, QR адреса через
  существующий qrcode-стек (`qrcode-kotlin`, 256×256 — как
  ReceiveScreen); ошибки — в `state.errorMessage`.

**`MsSendScreen`** (route `ms_send`; мутации `msBuildPsbt`,
`msBroadcastFinalized`; результаты в `state.msPsbt: String?`,
`state.msFinalTxid: String?`).

- Переиспользует state-контракт Send/UtxoPicker/Confirm из UI.md где
  применимо: destination/amount/fee/confirmations — та же семантика
  полей, что SendScreen; выбор входов — паттерн `utxo_picker` над
  набором `ms_unspent` (Coin Control, решение #12: полный набор +
  выбранное подмножество → `ms_build_psbt`).
- Контракт экрана — **излучить PSBT и принять PSBT назад**; раунды
  подписания косайнеров экраном не оркестрируются (out-of-band,
  транспорт — base64-PSBT):

  1. `Build` → `ms_build_psbt` → `state.msPsbt` (base64, shareable:
     copy + QR) + summary через `psbt_decode`; собственный ключ уже
     подписал (Creator + Signer за один шаг).
  2. Импорт combined+finalized PSBT (paste/QR-scan) → `psbt_decode`
     (превью) → `psbt_extract` → `broadcast` → `state.msFinalTxid`.

- State machine (конвенции UI.md: data-driven переходы, мутации
  только через VM, ошибки в `state.errorMessage`):
  `form → built → awaiting (out-of-band раунды) → imported →
  broadcast`; назад на любом шаге — без потери введённых N/M/ключей
  до успешного broadcast. Отказ импорта (не finalized, чужой кворум,
  битый base64) — конкретная ошибка FFI в `state.errorMessage`,
  состояние не сбрасывается.
- Cashback — на адрес кворума, не на личный адрес (см. «Поверхность»).

**Без изменений:** все 4 KDF и seed policy (R-1…R-7), WIF-поверхность,
адреса/скрипты, scan/selector/fee loop для личных адресов,
`send`-флоу, роли и сериализация PSBT (кроме зафиксированных
multisig-веток Creator/Signer/Finalizer), no-`unwrap`/newtype-политики,
решение #10.

### Тесты и quality gates

- **Coverage:** gate **lines=100 / branches=100** не ослабляется
  (каждый вариант `MsError`, каждая ветка Signer/Finalizer/Extractor,
  каждая строка таблицы «Валидация» — покрыты).
- **R-MS-1 pin («no default»):** `ms create`/`ms send` с пропущенным N
  или M — ошибка использования (subprocess-тест: exit ≠ 0, значение не
  подставляется); FFI-параметры n/m обязательны (compile-time); символа
  дефолта N/M в `fwd.rs` не существует (тест-гвард).
- **Граница R-MS-9 (const-гвард + векторы):** тест фиксирует
  `34·15 + 2 = 512 ≤ 520 < 546 = 34·16 + 2`; builder на N = 16 —
  `QuorumBounds` (все формы); N = 15 при form p2tr — валидный скрипт
  512 байт (wire-вектор KAT).
- **Скрипт-векторы (table-driven):** валидные/невалидные redeem-скрипты:
  границы `m`/`n` (0, 1, 15, 16), `OP_m > OP_n`, дубликаты, лишние
  байты, uncompressed-ключ в `0x21`-пуше, push-обёртки; builder↔extractor
  round-trip; адрес канонического набора — KAT. Tapscript-векторы:
  канонические формы для всех `1 ≤ M ≤ N ≤ 15` (builder↔extractor
  round-trip); невалидные: байт `0xae` (CHECKMULTISIG) в leaf,
  `NUMEQUALVERIFY`, 33-байтовый пуш ключа (`0x21`), дубликаты,
  OP_PUSHDATA-обёртки, лишние байты — конкретный вариант ошибки, без
  паник.
- **Consensus-behavior pins CHECKMULTISIG:** scriptSig, собранный
  Finalizer'ом, проверяется независимым reference-evaluation
  (Python: чистая реализация стек-семантики CHECKMULTISIG + ECDSA-
  верификация поверх sighash от `transaction.py`); мутации дают
  ожидаемые отказы: непустой dummy (BIP-147), переставленные подписи,
  подпись чужим ключом.
- **Consensus-behavior pin CHECKSIGADD:** итоговый witness проверяется
  независимым reference-evaluation (Python: стек-семантика
  CHECKSIG/CHECKSIGADD/NUMEQUAL по BIP-342 + BIP-340-верификация поверх
  `tapscript_sighash`); мутации дают ожидаемые отказы: подпись не в
  своём слоте (fail консенсуса), непустой слот не-подписанта (fail),
  все N слотов подписаны (счётчик N ≠ M — fail), пустой слот
  подписанта (счётчик < M — fail), изменённый control block
  (`UtxoMismatch` ещё на Signer).
- **PSBT round-trip M-of-N (синтетические ключи):** sign A → sign B →
  combine (коммутативность уже закреплена PSBT-property) →
  finalize → extract; property (≥ 1000 cases): перестановка аргументов
  ключей даёт тот же адрес (R-MS-4), произвольный порядок вставки
  `PARTIAL_SIG` — тот же итоговый scriptSig; для p2tr — произвольный
  порядок вставки `TAP_SCRIPT_SIG` — тот же итоговый witness.
- **2-of-3 e2e (p2sh):** три синтетических ключа (один — derived от
  фиксированного seed), два подписанта, полный конвейер `ms send`
  (mock-бэкенд) → `psbt sign` ×2 → `combine` → `finalize` → `extract`;
  итоговая tx верифицируется независимым OP_CHECKMULTISIG-эквивалентом
  (Python-reference) и KAT wire-hex.
- **e2e 2-of-3 P2WSH (mock-бэкенд):** полный конвейер
  `ms send --form p2wsh` → `psbt sign` ×2 → `combine` → `finalize` →
  `extract`; итоговая tx верифицируется независимым
  reference-evaluation (Python: стек-семантика CHECKMULTISIG над
  witness-стеком + BIP-143-верификация поверх `transaction.py`),
  мутации дают ожидаемые отказы (непустой dummy, переставленные
  подписи, подпись чужим ключом, `FINAL_SCRIPTSIG` на P2WSH-входе);
  consensus-behavior pin: witness-стек финализатора репроюсится через
  независимый интерпретатор.
- **PSBT round-trip 2-of-3 p2tr (синтетические ключи):** sign A →
  sign B → combine → finalize → extract (mock-бэкенд).
- **Крипто-векторы:** leaf_hash/tweak/control block — на BIP-341
  wallet test vectors (scriptPubKey-набор, одиночные листья) +
  собственные KAT от `yubtc-python`; sighash script-path —
  фиксированный вектор (SigMsg 174 байта + ext 37) в KAT.
- **Fuzz:** `fuzz_psbt` расширяется фазой redeem-скриптов: произвольные
  байты подставляются в `REDEEM_SCRIPT` → Signer/Finalizer/Extractor не
  паникуют (неканоничное — `UnsupportedInputScript`, без паник/OOM;
  лимит `PSBT_MAX_SIZE`); tapscript-фаза: произвольные байты в keydata
  `0x15` (control block) и value (script ‖ leaf_version) → парсер
  Signer/Finalizer не паникует.
- **Смоуки:** `ms create` на фиксированном кортеже == KAT-адрес;
  `ms send` под mock — base64 первого шага == KAT; отказ
  `NotAParticipant` на чужом кворуме; `ms create --form p2tr` на
  фиксированном кортеже == KAT-адрес; `--form p2tr` с
  compressed-ключом — `InvalidKeyEncoding`; личный `send` на
  tapscript-получатель и P2WSH-получатель сохраняет typed-отказ
  (guard CLI-слоя).

### Закреплённые решения

Решения приняты и реализованы; нормативные формулировки — в правилах
разделов выше. Изменение решения — запись в `DEVIATIONS.md`.

- **ОВ-10 (какой из наших ключей участвует).** Наш ключ в кворуме — legacy-ключ (P2PKH-деривация) на nonce `-n` — тот же ключ, что `dumpprivkey -n X`, для всех KDF; в FFI nonce — явный параметр. BIP-45/48-стиль не вводится.
- **ОВ-11 (формат ключей косайнеров).** Только compressed hex-pubkeys (для p2tr — x-only, R-MS-10); WIF — только для собственного ключа и только при совпадении с деривированным на `-n` (`ForeignWif`); watch-only-импорт чужих WIF не поддерживается.
- **ОВ-12 (`ms send` — обёртка или ручной конвейер).** Тонкая обёртка над существующими этапами (Creator-логика `psbt create` + Signer `psbt sign`), без нового кода криптографии/сериализации; отдельной команды `ms sign` нет.
- **ОВ-13 (политика адресов кворума).** Один фиксированный адрес на кортеж (N, M, множество ключей) — BIP-67-сортировка делает адрес инвариантным к порядку аргументов; scan/gap-обхода для кворумных адресов нет, баланс — прямой `get_unspent(address)`; деривация набора кворумных адресов из nonce не делается.
- **ОВ-14 (Android-поверхность multisig).** Полный surface — CLI + FFI + Android UI (решение владельца 2026-09-02, вместо FFI-only); перечень дополнений FFI и контракты экранов — «Принято (2026-09-02): полный surface» выше.
- **ОВ-15 (NUMS-внутренний ключ).** `H =
  lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)`
  — NUMS-точка из текста BIP-341 (`MS_TAPSCRIPT_INTERNAL_KEY`;
  «nothing up my sleeve» в первоисточнике, самовоспроизводимо в обоих
  портах). Рандомизация `H + rG` и сторонние каталоги NUMS-точек
  отвергнуты. Приватностный нюанс: наблюдатель может вычислить tweak
  от `H` и убедиться, что адрес script-path-only.
- **ОВ-17 (sighash и длина partial sig).** SIGHASH_DEFAULT (`0x00`),
  подписи ровно 64 байта (`aux_rand` — ОВ-3); `SIGHASH_TYPE`
  принимается только absent/`0x00`; 65-байтовые подписи (с байтом
  sighash) не пишем, чужие — вход пропускается (Signer) / блокирует
  финализацию (Finalizer).
- **ОВ-18 (BIP-32 taproot-поля PSBT).** `TAP_BIP32_DERIVATION (0x16)`
  — preserve-only (ОВ-9-паттерн): пути и leaf-hashes BIP-32 не пишем
  и не интерпретируем; Signer игнорирует поле целиком, идентификация
  «своих» — walk по nonce.
- **ОВ-19 (Android-поверхность tapscript).** Полный surface — CLI +
  FFI + Android UI (по прецеденту ОВ-14): третий сегмент селектора
  формы, vsize/dust-отображение p2tr-входов, JVM-паритет `MsQuorum`
  для трёх форм.

## Network backends

### Trait

```rust
#[async_trait]
pub trait NetworkBackend: Send + Sync {
    async fn get_unspent(&self, address: &TAddress) -> Result<Vec<Utxo>, NetError>;
    async fn get_info(&self, address: &TAddress) -> Result<AddressInfo, NetError>;
    async fn broadcast(&self, raw_tx: &[u8]) -> Result<(), NetError>;
    async fn raw_transaction(&self, txid: &str) -> Result<String, NetError>;
    fn name(&self) -> &'static str;
}
```

### Иерархия

```
NetworkBackend (trait)
├── BlockchainInfoBackend            # собственный API (raw_addr, unspent_outputs)
└── EsploraBackend (parent class)    # общая логика для Esplora-совместимых
    ├── BlockstreamBackend           # https://blockstream.info/api
    └── MempoolSpaceBackend          # https://mempool.space/api
```

`EsploraBackend` инкапсулирует общий код Esplora-формата (`GET /address/{addr}/utxo`, `GET /address/{addr}` с `chain_stats`/`mempool_stats`). См. `yubtc-python/src/yubtc/net.py`.

### Реестр (`core/src/net/mod.rs`)

Реестр — чистый `match` имени → новый экземпляр (без глобального
состояния; бэкенд передаётся владельцу явно — «Явная передача
бэкенда» ниже):

```rust
pub fn get_backend(name: &str) -> Result<Arc<dyn NetworkBackend>, NetError> {
    get_backend_with_retries(name, DEFAULT_HTTP_RETRIES)
}

pub fn get_backend_with_retries(
    name: &str,
    retries: u32,
) -> Result<Arc<dyn NetworkBackend>, NetError> {
    let policy = RetryPolicy::new(retries);
    match name {
        "blockchain.info" => Ok(Arc::new(BlockchainInfoBackend::with_policy("https://blockchain.info", policy))),
        "blockstream"     => Ok(Arc::new(BlockstreamBackend::with_policy("https://blockstream.info/api", policy))),
        "mempool.space"   => Ok(Arc::new(MempoolSpaceBackend::with_policy("https://mempool.space/api", policy))),
        "auto"            => Ok(Arc::new(AutoBackend::new(get_backends_for_auto_with_policy(policy)))),
        "mock"            => { /* URL из YUBTC_MOCK_BACKEND_URL, иначе UnknownProvider */ }
        other => Err(NetError::UnknownProvider(other.to_string())),
    }
}
```

Имена ключей — **как в yubtc-python** (1:1 для совместимости с `--provider`). `mock` — точка входа кросс-компат харнеса; в `auto`-порядок не входит (см. «Failover и retry»).

### Реализации

| Backend | URL | Родитель | Особенности |
|---|---|---|---|
| `BlockchainInfoBackend` (default) | `https://blockchain.info` | — | Собственный API (не Esplora), исторический fallback, default для совместимости с yubtc-python |
| `BlockstreamBackend` | `https://blockstream.info/api` | `EsploraBackend` | Esplora-based, быстрый |
| `MempoolSpaceBackend` | `https://mempool.space/api` | `EsploraBackend` | Esplora-based, лучший uptime |

### Унифицированный `Utxo`

Все backend'ы возвращают **одинаковый** тип `Utxo`, скрывая различия API:

```rust
pub struct Utxo {
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount: u64,          // satoshi
    pub script_pubkey: Vec<u8>,
    pub confirmations: u32,   // 0 = unconfirmed (mempool)
}
```

- **EsploraBackend:** `status.confirmed` + `status.block_height` + `chain.tip.height` → `confirmations = tip - block_height + 1`. Unconfirmed → 0.
- **BlockchainInfoBackend:** API отдаёт `confirmations` напрямую (но проверяем на >0; иначе 0).

`_select_inputs` фильтрует по `confirmations >= threshold` (default `DEFAULT_CONFIRMATIONS = 6`) без знания о backend API. Источник: `yubtc-python/src/yubtc/fwd.py`, `yubtc-python/src/yubtc/net.py`, `yubtc-python/src/yubtc/wallet.py`.

### Выбор backend

**CLI:**
```sh
yubtc balance                                # blockchain.info (default)
yubtc balance --provider blockstream         # blockstream.info
yubtc balance --provider mempool.space       # mempool.space
```

Только `--provider NAME` флаг. Env-переменной `YUBC_PROVIDER` нет.
- Settings screen → radio buttons: blockchain.info / blockstream / mempool.space.
- Persisted в обычном `SharedPreferences` (не sensitive — это просто строка).
- Default: `blockchain.info`.

**Selection logic** (`core/src/net/mod.rs`):
```
priority: --provider flag > android prefs (in app) > "blockchain.info"
```

### Failover и retry

Resilience-слой — **opt-in**: default остаётся `blockchain.info`
(бит-в-бит совместимость с первоначальным поведением), automatic
failover включается явно (`--provider auto`). Без него фоллбэка нет:
если primary backend возвращает 5xx или timeout — возвращаем ошибку,
пользователь сам переключает провайдера (`--provider` / настройки в
приложении); silent failover маскирует деградацию бэкенда и делает
источник данных неявным для пользователя (политика «no silent
fallbacks»).

**1. Retry (per request, per backend).** Каждый HTTP-запрос выполняется
до `1 + N` раз (N = `--retries`, default `DEFAULT_HTTP_RETRIES = 3`;
`0` — ровно одна попытка). Между попытками —
экспоненциальная задержка с потолком: `HTTP_RETRY_BASE_DELAY_MS = 500`
→ 1 s → 2 s (`HTTP_RETRY_MAX_DELAY_MS = 2000`, дальше не растёт).
Retryаются: транспортные ошибки (connect/timeout/reset) и статусы
5xx, 408, 429. **Не** retryаются: прочие 4xx (детерминированный отказ —
повтор только продублирует его) и ошибки декодирования тела
(статус уже 2xx). Для 429 делается попытка honour `Retry-After`
(целые секунды, `HTTP_RETRY_AFTER_MAX_SECS = 30` — за пределами окна,
нечисловые (HTTP-date) и отрицательные значения игнорируются в пользу
обычного backoff, чтобы сервер не мог парковать кошелёк одним
заголовком). Контракт на терминальную ошибку: после исчерпания попыток
пользователь получает **тот же тип и текст**, что и единичная попытка
без retry (`BadResponse`/`Broadcast`/`Http`) — retry не искажает
диагностику. Retry живёт в HTTP-слое (`net::send_with_retries`), а не
вокруг `NetworkBackend`-trait'а: только там ещё различимы сырой статус
и транспортная ошибка, по которым принимается решение. `NetworkBackend`
trait не меняется. broadcast-POST retryается наравне с GET: повторная
отправка того же tx идемпотентна по сути (один txid, сеть дедуплицирует).

**2. Failover (`--provider auto`).** Псевдо-провайдер `auto` (не
default): на каждый запрос обходится реестр по порядку
`blockchain.info → blockstream → mempool.space`
(`net::get_backends_for_auto()`), первый успех побеждает и
запоминается (sticky) до конца запуска команды — состояние
внутри `AutoBackend` в памяти handle'а, никогда не на диске и не
между процессами (stateless wallet). Запомненный backend, начав
отказывать, естественным образом демонтируется: обход начинается с
него и продолжается по порядку реестра, следующий успех пере-закрепляется.
`mock` в auto-порядок **не входит** (это точка входа кросс-компат
харнеса, не реальный провайдер). `get_backend(name)` сохраняет
точное разрешение имени; `auto` — просто ещё одно имя реестра.

**3. Ошибки.** После исчерпания всех backend'ов — типизированная
`NetError::AllBackendsFailed` со следов попыток (`name: последняя
ошибка`, через `; `, в порядке обхода). Семантика exit-code не
меняется (Network → 1).

**4. Конфигурация.** Константы — в `fwd.rs` (см. «Defaults — единый
источник правды»); CLI-флаг `--retries N` (входит в общую
`ProviderOpt`-группу всех сетевых команд); uniffi-изменений нет —
`WalletHandle` принимает backend по имени, `"auto"` работает через
тот же механизм (см. doc `set_backend`); Android — без изменений.

**5. Python-зеркало.** `yubtc-python` повторяет поверхность 1:1
(`--retries`, `--provider auto`, `get_backend(name=, retries=)`,
`AutoBackend`, `AllBackendsFailed`, те же константы в `fwd.py`);
сетевое поведение не обязано быть бит-в-бит (Python-специфика
проглатывания `JSONDecodeError` сохраняется как есть).

### Явная передача бэкенда

Бэкенд всегда передаётся явно — процесс-глобального канала доставки
бэкенда не существует (реализовано 2026-08-19, merge `61d19cc` +
`42bbaa7`; Python-референс — `yubtc-python` `3d053a7`).

**Архитектура.**

1. **Реестр остаётся** чистой функцией без состояния — текущий
   `net::get_backend(name) -> Arc<dyn NetworkBackend>` уже им и
   является (резолвит имя → новый экземпляр; `"mock"` читает
   `YUBTC_MOCK_BACKEND_URL`). Реестр ничего не хранит.
2. **Глобала нет.** Процесс-глобальный `CURRENT_BACKEND` с
   `current()`/`set/reset`-API не существует; все сетевые вызовы идут
   через явно переданный экземпляр.
3. **Бэкенд — поле владельца**: `Wallet { backend:
   Arc<dyn NetworkBackend>, ... }` (и производные `TPrivKey`-кэши
   через владельца). `Wallet::new(..., backend: Arc<dyn
   NetworkBackend>)` получает уже резолвнутый экземпляр. Аналогично
   `WalletHandle` (uniffi): конструктор принимает `backend:
   Option<String>` — резолвнутый `Arc` хранится в handle.
4. **Свободные функции** (`broadcast_tx` и т.п.) принимают бэкенд
   параметром: `net::broadcast(backend, raw_tx)`. Неявного «current»
   нет нигде.
5. **CLI**: `cmd::*::run` резолвит `--provider` через `get_backend`
   один раз и передаёт вниз. Поведение пользователя не меняется.
6. **Тесты**: мок передаётся явно (в `Wallet::new` / напрямую в
   свободные функции). Исключение — `#[serial]` на wiremock-тестах
   uniffi (гонка `MockServer::start` самой библиотеки —
   задокументировано на месте в `core/src/uniffi_api.rs`).

**Плюсы:** устранение класса флапов; per-handle бэкенды (Android —
разные провайдеры на экран/кошелёк); явные зависимости (соответствует
политике «no silent fallbacks»); упрощение тестов.

**Python-референс мигрирует вместе с Rust** (единая архитектура
обоих портов, расхождения нет): глобальный `_current_backend` в
`net.py` отсутствует, `Wallet.__init__`/`TPrivKey` хранят переданный
бэкенд, свободные функции принимают его параметром.

**Контрактное правило на будущее:** любое новое сетевое взаимодействие
принимает `&dyn NetworkBackend`/`Arc<dyn NetworkBackend>` явно.
Создание новых глобальных каналов доставки бэкенда запрещено.

## Defaults — единый источник правды

Все defaults централизованы в `core/src/fwd.rs` (аналог `yubtc-python/src/yubtc/fwd.py`). CLI/UI берут значения отсюда, не из собственных констант.

| Константа | Значение | Где используется |
|---|---|---|
| `DEFAULT_NONCE` | `0` | `address`, `balance`, `dumpprivkey`, `send` (без `-n`) |
| `DEFAULT_SEED_WORDS` | `15` | `newseed -n` |
| `DEFAULT_NEW_ADDRESSES` | `1` | `address --new`, `balance --new` |
| `DEFAULT_CONFIRMATIONS` | `6` | `balance -c`, `send -c` (фильтр UTXO по подтверждениям) |
| `DEFAULT_TIMEOUT_HTTP` | `5` (сек) | HTTP-запросы ко всем backend'ам. Backend'ы обязаны отвечать за секунды; 180-секундный fallback маскирует зависание API и замораживает кошелёк — для UX неприемлемо. |
| `DEFAULT_HTTP_RETRIES` | `3` | Retry-попыток на HTTP-запрос (`--retries`; см. «Network backends → Failover и retry»). `0` = одна попытка. |
| `HTTP_RETRY_BASE_DELAY_MS` | `500` | База экспоненциального backoff между retry-попытками (500 ms → 1 s → 2 s…). |
| `HTTP_RETRY_MAX_DELAY_MS` | `2000` | Потолок backoff: попытки не ждут дольше 2 s независимо от номера. |
| `HTTP_RETRY_AFTER_MAX_SECS` | `30` | sane-окно `Retry-After` на 429: за пределами (или нечисловое) — обычный backoff. |
| `DEFAULT_FEE` | `0` BTC | `send -f` |
| `DEFAULT_PASSPHRASE` | `""` | Passphrase prompt (пустой ввод = no passphrase) |
| `MIN_ENTROPY_WARNING_BITS` | `128` | Порог warning по оценке энтропии фразы (`bits = length * log2(\|charset\|)`); ниже порога — предупреждение, приём продолжается (см. «Seed policy», R-6). Не блокирует. |
| `DEFAULT_ALLOW_DUPS` | `true` | BIP-39 wordlist validation |
| `DEFAULT_LOCKTIME` | `0` | Все исходящие tx |
| `SEQUENCE_RBF_SIGNALED` | `0xfffffffe` | Все исходящие tx (BIP-125 RBF signal) |
| `EMPTY_SCRIPT` | `b""` | Дефолт для CScript |
| `DEFAULT_MIN_RELAY_TX_FEE` | `1000` sat/kvB (= 1 sat/vB) | Relay floor Bitcoin Core (`policy/policy.h`). Не наша константа — берётся из `bitcoin` crate (`bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE`) либо из fee-estimator'а Bitcoin Core, **не дублируется** в `fwd.rs`. См. «Fee loop и dust». |
| `DEFAULT_FEEKB` | `1000` sat/kB (1 sat/vB) | Default feerate в `send` без `-f`/`-k`. Адекватно для нормальной загрузки сети; tx обычно попадает в следующий блок. Отличается от yubtc-python (там `MINIMAL_FEE = 2000 sat` как default). |
| `DEFAULT_ADDR_TYPE` | `Native` | Форма адреса получения по умолчанию (`--addr-type`; ОВ-1). Пути `m/84'/…`/`m/86'/…` — шаблоны деривации. |
| `DUST_THRESHOLD_P2PKH` | `546` sat | Минимальный size валидного P2PKH выхода (Bitcoin Core) |
| `DUST_THRESHOLD_P2SH` | `540` sat | Минимальный size валидного P2SH выхода (Bitcoin Core) |
| `DUST_THRESHOLD_P2WPKH` | `294` sat | Минимальный size валидного P2WPKH выхода (см. «Fee loop и dust») |
| `DUST_THRESHOLD_P2WSH` | `330` sat | Минимальный size валидного P2WSH выхода (см. «Fee loop и dust») |
| `DUST_THRESHOLD_P2TR` | `330` sat | Минимальный size валидного P2TR выхода (см. «Fee loop и dust») |
| `PSBT_MAX_SIZE` | `4 MiB` | Лимит размера PSBT (fuzz/OOM-гвард; см. «PSBT — BIP-174 → Сериализация») |
| `PSBT_SIGN_MAX_NONCE` | `1000` | Верхняя граница офлайн-walk'а Signer'а по nonce (ОВ-9) |
| `MS_MAX_PUBKEYS` | `15` | Верхняя граница N — единая для всех форм кворума (R-MS-2/R-MS-9). Дефолтов N/M нет (R-MS-1). |
| `MS_TAPSCRIPT_INTERNAL_KEY` | x-only `50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0` | NUMS-внутренний ключ tapscript-кворума (R-MS-8, ОВ-15) |
| `MS_SIG_SIZE_ESTIMATE` | `73` | Worst-case оценка подписи в fee loop (P2WSH-multisig-вход) |
| `MS_SIG_SIZE_ESTIMATE_TAP` | `66` | Worst-case оценка Schnorr-слота (p2tr-вход) |

Дефолтов N/M/формы multisig в `fwd.rs` нет (R-MS-1; CLI-default `p2sh`
живёт только в argparser и задокументирован — см. «Multi-sig →
Поверхность»).

### Удалённые константы

- **`_FEE_LOOP_MAX`** — safety net для pathological feerate, обещанный в
  spec как «cycle detection обычно ловит за 3-5 iter». В Rust port
  цикл строит `BTreeMap<size, candidates>` (см. «Fee loop и dust»),
  поэтому зацикливание невозможно в принципе — cycle = «новый fee для
  уже встречавшегося size, который не попал в map». Iteration cap
  добавлять не нужно. Константа удалена как мёртвый код.

Источник остальных констант: `yubtc-python/src/yubtc/fwd.py`.
Bit-for-bit compatibility — обязательна для констант, унаследованных
от yubtc-python (история — в git). Relay floor (`DEFAULT_MIN_RELAY_TX_FEE`)
в Rust-порте **берётся напрямую** из `bitcoin` crate и не дублируется в
`fwd.rs`; в Python-референсе — константа `MIN_RELAY_TX_FEE` в `fwd.py`
(1000 sat/kvB, тот же источник). Flat-константа `MINIMAL_FEE` в Python
остаётся только как default CLI-флага `--feekb` (2000 sat/kB) и в
fee-loop не участвует.

## CLI — команды

Полная копия yubtc-python (passphrase запрашивается интерактивно, как
в Python); расширения флагов Rust-CLI — `--strict-bip39` (2026-08-28,
D-001, см. «Ключи и seed → Seed policy»), `--kdf`, `--addr-type` и
`--retries` (см. «Network backends → Failover и retry»); группы
`psbt`/`ms` — разделы «PSBT — BIP-174 → CLI» и «Multi-sig →
Поверхность»:

```
yubtc newseed [-n WORDS] [--unique] [--addr-type T]
yubtc address [-n NONCE] [--new N] [--kdf NAME] [--addr-type T]
              [--strict-bip39] [--provider NAME] [--retries N]
yubtc dumpprivkey [-n NONCE] [--kdf NAME] [--addr-type T]
              [--strict-bip39] [--provider NAME] [--retries N]
yubtc balance [-n NONCE] [-c CONFIRMATIONS] [--new N] [-e] [-v]
              [--kdf NAME] [--addr-type T] [--strict-bip39]
              [--provider NAME] [--retries N]
yubtc send ADDR AMOUNT [-n NONCE] [-c CONFIRMATIONS] [-f FEE] [-k FEEKB]
            [--broadcast] [--scan] [-i] [-y] [--kdf NAME] [--addr-type T]
            [--strict-bip39] [--provider NAME] [--retries N]
yubtc pushtx [-y] [--provider NAME] [--retries N]
```

**Совместимость с yubtc-python:**
- Все позиционные аргументы и флаги — 1:1 с
  `yubtc-python/src/yubtc/cli.py`; Rust-расширения — `--provider`,
  `--retries`, `--kdf`, `--addr-type`, `--strict-bip39`.
- `-n NONCE` на `send` есть в обоих портах (явный выбор
  source-адреса; без него — scan → greedy selector → send).
- **Расширение (2026-08-28, D-001):** `--strict-bip39` — опциональный
  strict-режим приёма seed: полный BIP-39 parse + C6 entropy floor,
  отказ блокирующий (см. «Seed policy», R-3…R-5). Default —
  permissive: любая непустая фраза; при оценке энтропии `< 128` бит
  CLI печатает warning и продолжает работу (R-6). Флаг поддерживают
  команды с вводом seed (`address`, `balance`, `dumpprivkey`,
  `send`); `newseed` генерирует seed сам и флага не имеет.
- **Отклонение от Python (2026-08-18):** `newseed` не строит `Wallet` и не ходит в сеть. Адрес выводится напрямую из `(seed, nonce=0)` тем же KDF (yubtc cascade, без passphrase) — вывод байт-в-байт совпадает с Python (у Python `privkeys[0]` для свежего seed — тоже nonce-0: gap-scan сразу останавливается, а `DEFAULT_NEW_ADDRESSES=1` добавляет тот же ключ). Отличие только в отказоустойчивости: python-версия делает один `get_info` и падает при недоступном бэкенде, Rust-версия работает офлайн. Причина: сетевой вызов для brand-new seed не несёт информации (истории нет по определению).
- Без `--provider` — `blockchain.info` (default; совпадает с yubtc-python). Другие варианты: `blockstream`, `mempool.space`.
- Passphrase — через интерактивный prompt (tty → `getpass`, non-tty → `readline`); как в yubtc-python. CLI-флага нет.

### `send` flow (Python parity)

```rust
// cli/src/cmd/send.rs (псевдокод)
fn send(dst: &str, amount_btc: &str, ...) -> Result<()> {
    let amount_sat = btc_to_satoshi(amount_btc)?;
    let fee_sat = compute_fee_sat(...);
    
    // Шаг 1: scan до достаточной суммы (matches Python _scan_inputs)
    let (selected, cashback_addr) = handle.select_inputs_until(
        Some(amount_sat + fee_sat),
        confirmations,
    )?;
    
    // Шаг 2: build tx с выбранными UTXO
    let utxos = fetch_unspent_for_selected(&selected)?;  // или принимаем из scan
    let tx = handle.make_transaction_multi(
        utxos,
        selected,
        cashback_addr,
        dst,
        Some(amount_sat),
        feekb_sat,
        fee_sat,
    )?;
    
    // Шаг 3: broadcast (опционально)
    if broadcast { handle.broadcast(&tx.tx_hex)?; }
}
```

Network calls: **2** (1 scan + 1 broadcast). Минимум — не пересканировать после scan'а.

### Logging policy

`tracing` подключён как зависимость, но subscriber инициализируется
**только** под `#[cfg(debug_assertions)]` или через environment gate
`YUBTC_LOG=<level>` (решение C7, `cli/src/logging.rs`). В
release-сборках (без env var) логи молчат.

- **Release без `YUBTC_LOG`** — никакого вывода. Приватные данные
  (seed, passphrase, WIF) никогда не попадают в логи даже под debug.
- **`YUBTC_LOG=error|warn|info|debug|trace`** (регистронезависимо) —
  инициализация stderr-subscriber'а CLI с этим уровнем. Некорректное
  значение не роняет команду — откатывается к default (debug-сборка:
  `debug` в stderr; release: молчание). Android-слой subscriber не
  инициализирует (молчит всегда); seed/passphrase/wif запрещены к
  логированию на любом уровне (явный review каждого `info!`).
- **Тесты** — `YUBTC_LOG=debug` не должен ничего писать в stderr, не
  подкручивая test harness. Если тесту нужны логи — явно через
  `tracing_subscriber::fmt().with_writer(...)`.

Это не «feature flag» в смысле опции для пользователя — это политика,
по умолчанию действующая в release. Пользователь не должен видеть
debug-вывод кошелька с деньгами.

## Android / uniffi

### Безопасность

**Принцип: кошелёк stateless by design.** Seed + passphrase живут в памяти **только**, в `WalletHandle`. Закрытие приложения, переключение на другой экран, lock — handle уничтожается, seed wiped из памяти. Никаких `EncryptedSharedPreferences` для seed, никакой биометрии на cold launch (бессмысленно — seed всё равно придётся вводить заново).

См. README: *"Downloads nothing, stores nothing on disk: private keys are derived from a seed on each invocation."*

- `android:allowBackup="false"` в манифесте.

Детект root (`RootBeer`) и `FLAG_SECURE` на MainActivity —
рассматривались, но не реализованы (снято при аудите 2026-09-07;
`MainActivity` не ставит `FLAG_SECURE`, root-детекта нет).

### Wipe-on-lock (по умолчанию включено)

`ProcessLifecycleOwner`: на `ON_STOP` стартует coroutine с задержкой
`idleMinutes * 60_000` (защита от ложных срабатываний — открыл шторку
уведомлений, назад в приложение), на `ON_START` — отменяется; по
истечении вызывается `vm.lock()` → handle уничтожается.
`LockScheduler` перепроверяет `wipeOnIdle` перед `lock` (race между
тапом toggle и истечением таймера).

**SettingsScreen** содержит Switch «Wipe wallet when leaving the app»
(default **ON**) + chip-group задержки `1 min` / `5 min` / `15 min`
(default **5**; вне диапазона значения клампятся
`SettingsRepository`). Настройки хранятся в обычном
`SharedPreferences` (не зашифрованном — это просто toggle, не
sensitive).

Когда чекбокс **OFF** — wallet остаётся в памяти даже при уходе в фон (удобство > паранойя).

### UI (Compose Material 3)

Экраны (детальные контракты — `specs/UI.md`):

- **passphrase** (`PassphraseScreen`) — первый экран при запуске
  (Locked): поля seed (multi-line) + passphrase
  (`PasswordVisualTransformation`), кнопки `Unlock` / `Generate`
  (сгенерированный seed — в `state.generatedSeed` с `Copy`/`Use`/
  `Dismiss`). Приём seed — R-1…R-7: оценка энтропии `< 128` бит →
  карточка «Low entropy» с `Continue`/`Edit` (не блокирует); настройка
  `strict_bip39` добавляет блокирующий BIP-39 parse + entropy floor.
- **home** (`HomeScreen`) — `Card` баланса (`finalBalanceSat` из
  `address_info`) + total received + `n_tx`, адрес, Row `Send` /
  `Receive` + Row `Settings` / `Lock`, кнопка `Refresh balance`
  (перезапускает scan).
- **send** (`SendScreen`) — форма: To, Amount + Switch «Send max»
  (drain), Fee slider (1–20 sat/vB), Confirmations chips (`0`/`1`/`6`),
  «Pick inputs» (Coin Control picker), «Request this amount instead»
  (BIP-21 prefill на Receive), кнопка Build → Confirm.
- **utxo_picker** (`UtxoPickerScreen`, Coin Control) — `LazyColumn`
  всех UTXO из `state.unspent` с колонкой nonce + txid + vout + amount
  + conf. Row `All` / `Auto` / `None`, `Cancel` / `Confirm`.
- **confirm** (`ConfirmScreen`) — Amount / Fee / Cashback / Txid /
  Network txid + raw hex, кнопка Broadcast.
- **receive** (`ReceiveScreen`) — QR 256×256 (`qrcode-kotlin`) + BIP-21
  URI: amount/label/message поля; при переходе из Send с
  `initialAmountBtc` поле amount предзаполнено, QR кодирует
  `bitcoin:<address>?amount=<btc>`; кнопка Copy URI.
- **settings** (`SettingsScreen`) — chip-group backend
  (blockchain.info / blockstream / mempool.space), Switch «Wipe on app
  leave» + чипы задержки, переключатель «Strict BIP-39» (настройка
  `strict_bip39`, bool, default `false`, R-3), Lock wallet.
- **ms_create / ms_send** (`MsCreateScreen` / `MsSendScreen`) —
  кворумные экраны (контракты — «Multi-sig → Принято (2026-09-02):
  полный surface» и `specs/UI.md`).

### Background work

- Все network-вызовы через `viewModelScope.launch` c
  `catch (YubtcException)` → `state.errorMessage` — без uncaught
  exception'ов на main thread.
- Единый `YubtcState` (state-таблица — `specs/UI.md`): `status`, `unspent`,
  `selectedUtxos`, `lastTx`, `lastTxid`, `errorMessage`, ms-поля и т.д.
- Никакой блокировки main thread.

### UniFFI export (обновлённая поверхность)

```idl
// #[uniffi::export] в core/src/uniffi_api.rs (Rust 0.32+)
namespace yubtc {
    // Scan (network)
    [Throws=YubtcError] sequence<UtxoWithNonce> all_unspent(u32 confirmations);
    [Throws=YubtcError] SelectInputsResult select_inputs_until(u64? target_sat, u32 confirmations);

    // Pure (no network)
    sequence<SelectedSource> default_selection(
        sequence<UtxoWithNonce> utxos,
        u64? target_sat
    );
    [Throws=YubtcError] TxResultRecord make_transaction_multi(
        sequence<UtxoWithNonce> utxos,
        sequence<SelectedSource> selected,
        string cashback_addr,
        string dst,
        u64? amount_sat,
        u64 feekb_sat,
        u64 fee_sat
    );

    // Broadcast
    [Throws=YubtcError] string broadcast(string raw_tx_hex);

    // Lifecycle
    [Throws=YubtcError] void set_backend(string? name);
};

// Расширения WalletHandle — см. «PSBT — BIP-174» и «Multi-sig»:
// psbt_sign / psbt_extract / psbt_decode /
// ms_create_address / ms_unspent / ms_build_psbt
// (+ p2pkh_address / receiving_address, конструктор с AddrTypeName).

record UtxoWithNonce {
    u32 nonce;
    string txid_hex;
    u32 vout;
    u64 amount_sat;
    u32 confirmations;
    string script_type;   // "p2pkh" / "p2sh" / "p2wpkh" / "p2tr"
};

record SelectInputsResult {
    sequence<SelectedSource> selected;
    sequence<UtxoWithNonce> utxos;   // тот же набор, без повторного fetch
    string cashback_addr;
};

record SelectedSource {
    u32 nonce;
    string txid_hex;
    u32 vout;
};
```

### Rust API surface

| Модуль | Состав |
|---|---|
| `uniffi_api.rs` | `AddrTypeName { legacy, native, taproot }` в конструктор `WalletHandle::new` (default native), метод `receiving_address()`; `UtxoWithNonce` + `script_type: String` (`p2pkh`/`p2sh`/`p2wpkh`/`p2tr`) для Coin Control UI. Метод `p2pkh_address()` сохраняется как legacy-шорткат. PSBT: `psbt_sign(psbt_b64) -> String`, `psbt_extract(psbt_b64) -> String`, `psbt_decode(psbt_b64) -> PsbtSummary`; record `PsbtSummary { txid_hex, version, inputs: Vec<PsbtInputSummary>, outputs: Vec<PsbtOutputSummary>, fee_sat: Option<u64> }`; `PsbtError` маппится в `YubtcError` (как `TransactionError`); `psbt_create`/`combine`/`finalize` в FFI не выносятся: create требует сеть (у Android уже есть `all_unspent`+`make_transaction_multi`-путь `send`-флоу), combine/finalize не нужны UI; добавление — обратно совместимо. Multisig: `MsFormName` (uniffi::Enum: `p2sh`/`p2wsh`/`p2tr`); `ms_create_address`/`ms_build_psbt` — параметр `form`; полный ms-surface — «Multi-sig → Принято (2026-09-02): полный surface». Kotlin-bindings регенерируются (uniffi-bindgen 0.32.0). |
| Android | enum `AddrTypeSetting` в `SettingsRepository` (SharedPreferences, паттерн `strict_bip39`), radio на SettingsScreen; Receive/Home показывают адрес выбранного типа. PSBT — без изменений UI (ОВ-7): методы доступны через FFI, экранов нет; CI-дифф `bindings/kotlin/` обновляется автоматически. Multisig — `ui/screens/MsCreateScreen.kt`, `ui/screens/MsSendScreen.kt`; `YubtcNavHost` — routes `ms_create`, `ms_send`; `data/YubtcViewModel` — state-поля `msAddress: MsAddressRecord?`, `msPsbt: String?`, `msFinalTxid: String?` (мутации `msCreateAddress`/`msBuildPsbt`/`msBroadcastFinalized`); контракты — «Multi-sig → Принято (2026-09-02): полный surface». |

## Качество и CI

**Философия:** строгие политики, уменьшающие вероятность бага, **даже в ущерб производительности и удобству**. Yubtc работает с деньгами — лучше медленнее и явно, чем быстрее и непредсказуемо.

### Покрытие (non-negotiable)

- **Line + branch coverage:** **100% всегда**. Без исключений. Каждый PR, не дотягивающий до 100%, блокируется CI. Это не рекомендация — это gate.
- **Механизм:** `cargo-llvm-cov` на **nightly** (branch-метрика `--branch` нестабильна и nightly-only; lcov-форматтер LLVM nightly SIGSEGV с branch-данными, поэтому вход гейта — JSON): `cargo llvm-cov --workspace --all-features --branch --json --output-path cov-summary.json` — **без `--summary-only`**: гейту нужны per-function records и merged per-file segments. Терминальный код, не покрытый без реального TTY (`cli/src/prompt_tty.rs`, `cli/src/cmd/tui_term.rs`), исключён из измерения (`--ignore-filename-regex`). Пороги lines=100 и branches=100 проверяет `scripts/cov-gate.sh` (нативного `--fail-under-branches` в cargo-llvm-cov нет; скрипт используется и в CI, и локально). Начиная с 2026-09-07 (owner-approved carve-out) скрипт пересчитывает line-покрытие из merged segment-view (эквивалент рендерера `llvm-cov show`) и держит carve-out для dangling zero-count function-records: дубликат-инстанциация с count=0 не маскирует живые счётчики, но span каждой такой записи проверяется — реально мёртвая строка или односторонняя живая ветка роняют гейт (`--strict` отключает carve-out и берёт обе метрики из raw-summary). Branch-метрика — без изменений из fold-aware summary llvm-cov.
- Каждый `#[cfg(...)]` branch, каждый `match` arm, каждый `if let Some/None` — покрыт тестом.

### Политики против багов

- **Никаких `unwrap()` в non-test коде.** Только `expect("invariant: <reason>")` где инвариант документирован. `unwrap()` разрешён **только** в `tests/` и в `examples/`.
- **Никаких `panic!()` в production paths.** Все ошибки — `Result<T, E>` с типизированным `E`.
- **Никаких silent fallbacks.** Если два backend'а — два варианта; не "попробуй первый, если ошибка — попробуй второй" без явного разрешения.
- **Newtype wrappers для всех magic types:** `TSatoshi(u64)`, `TAddress(String)`, `TNonce(u32)`, `TSeed(String)`, `TPassphrase(String)`, `TBTC(Decimal-equivalent)`. Запрещено передавать голые `u64`/`String` туда, где ожидается satoshi/address.
- **Required fields — отдельные типы с `NotNone` sentinel** (как Python convention). `Wallet::new(seed: NotNone<TSeed>, nonce: NotNone<TNonce>)` — позиционные вызовы и отсутствующие поля дают compile-time ошибку, не runtime.
- **No `unsafe` в нашем коде.** `cargo geiger` = 0. `unsafe` в `bitcoin`/`k256` crates — задокументирован в `Cargo.lock` audit log.
- **No `#[allow(...)]` без `#[reason = "..."]`** и ссылки на issue.
- **KAT (Known-Answer Tests) для всех 4 KDF.** Без KAT нельзя рефакторить crypto. KAT-векторы хранятся в `core/tests/kat/` (`vectors.json`, `psbt_vectors.json`, `ms_vectors.json`), проверяются Rust-тестами `kat_vectors.rs` / `psbt_vectors.rs` / `ms_vectors.rs` на Rust ↔ Python совпадение; генератор — `yubtc-python` (`core/tests/kat/generate.py`). Матрица расширяется осями: `addr_type` (segwit/taproot-адреса для (KDF × nonce × seed), TapTweak, sighash-дайджесты, witness-hex; 16 базовых строк не пересчитываются — regression-гвард), PSBT (цепочка base64 unsigned → signed → finalized + extracted tx hex + unknown-поля) и multisig (три формы кворума — см. «Multi-sig → Python-зеркало»).
- **Property-based tests** на инварианты KDF/signing/base58/bech32/serialization/fee-loop (`proptest` crate). Число cases — как в коде: proptest defaults (256) у инвариантов KDF/seed/WIF; явные overrides (`Config::with_cases`) — 1000 у bech32/сериализации/PSBT/R-MS-4, 64 у fee-loop и privkey-clamp.
- **Fuzz tests** для всех parsers (Targets в `core/fuzz/fuzz_targets/`):
  - `fuzz_mnemonic.rs` — произвольный UTF-8 → валидация как BIP-39 мнемоника (`validate_seed`).
  - `fuzz_hex.rs` — произвольные байты → `hex::decode` → проверка что не паникует.
  - `fuzz_wif.rs` — произвольный base58check → `address::wif_to_secret` (единственный путь импорта ключа).
  - `fuzz_raw_tx.rs` — произвольные байты → `bitcoin::Transaction::consensus_decode` (raw tx).
  - `fuzz_bech32.rs` — произвольные строки → `bech32::decode`/`encode`/`decode_segwit_address`.
  - `fuzz_psbt.rs` — произвольные байты → `psbt::PartiallySignedTransaction::parse`.

  CI (`fuzz.yml`) — ночной прогон: **60 секунд** каждая цель
  (`workflow_dispatch` — ручной запуск). Corpus/crash-артефакты — в
  `core/fuzz/artifacts/`; PR-smoke отдельной джобы нет.

### Lints / static analysis

- **`cargo clippy -- -D warnings`** — все warnings как errors.
- **`cargo fmt --check`** — без исключений.
- **`cargo geiger`** в CI — count `unsafe` блоков.
- **`cargo audit`** — проверка известных CVE в зависимостях.
- **Зависимости — dependabot** (еженедельный отчёт,
  `.github/dependabot.yml`).

### Audit

- **Ручной review** KDF, signing, broadcast — **перед каждым релизом**.
- **Крипто-критичные изменения** требуют 2 reviewers, минимум 1 — не автор.
- **`Cargo.lock` audit log** — каждая зависимость с `unsafe` блоком имеет комментарий почему мы её используем.

### CI gates

Каждый PR должен пройти (`ci.yml`; push в `master`/`phase-*` и PR в `master`):
1. `cargo fmt --check`
2. `cargo clippy -- -D warnings`
3. `cargo test` (все unit + integration; ubuntu + macos + windows)
4. `cargo llvm-cov --branch` + `scripts/cov-gate.sh` — lines=100%, branches=100%
5. `cargo geiger` (≤ baseline)
6. `cargo audit`

(Android-джобы — `build-rust`/`bindings`/`unit-tests`/`apk` —
переехали в release-пайплайн `release.yml` и на PR не гоняются
(решение владельца 2026-09-05, `android.yml` слит в `release.yml`);
fuzz — только ночной прогон `fuzz.yml`.)

Release tags дополнительно (`release.yml`):
7. Manual audit checklist sign-off
8. cdylib × 3 Android ABI + bindings-drift + JVM unit-tests + `assembleDebug`/`assembleRelease`
9. APK (signed release build при наличии секрета; иначе debug-fallback)
10. GitHub Release (CLI-архивы 5 target-триплетов + APK; prerelease при `-` в теге)

### CI workflows

| Workflow | Triggers | Jobs | Артефакты |
|---|---|---|---|
| `ci.yml` | push (`master`, `phase-*`), PR (`master`) | `fmt`, `clippy`, `test` (ubuntu+macos+windows), `coverage` (linux, nightly, lines+branches gate), `geiger`, `audit` | cov-summary.json (full-detail, `--ignore-filename-regex` для терминального кода) |
| `codeql.yml` | push (`master`), PR (`master`) | `analyze` (rust; `continue-on-error` — недоступно для private repo) | CodeQL SARIF |
| `fuzz.yml` | nightly cron (02:07 UTC) + `workflow_dispatch` | `cargo fuzz` × N целей × 60 сек | corpus/crash — в `core/fuzz/artifacts/` раннера |
| `release.yml` | tag push (`v*`) | единый пайплайн (решение владельца 2026-09-05, `android.yml` слит сюда): `build-cli` × 5 target-триплетов, `build-rust` (cdylib × 3 ABI, NDK r27), `bindings` (drift-гейт), `unit-tests` (`:app:testDebugUnitTest`), `apk` (`assembleDebug` + `assembleRelease`, keystore из секрета / debug-fallback), `release` (softprops → GitHub Releases; prerelease при `-` в теге) | CLI-архивы `yubtc-<version>-<target>` + APK `yubtc-<version>-{release,debug}.apk` в одном GitHub Release |

Secrets: `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`.

## Управление проектом

*(консолидировано из roadmap-файла, 2026-09-05)*

Roadmap-файл с фазами и сводом принятых решений консолидирован
в этот документ и удалён; статусы фаз — в `README.md` (Status),
история работы над фазами — в git. Технические решения слиты
с существующими разделами этой спеки; здесь остаются только
проектно-управленческие политики.

### Scope-policy

Авторитетный список always-out-of-scope — раздел «Безопасность: что
мы НЕ делаем» выше; отклонённые предложения — «Отклонённые
предложения». Других списков scope нет.

### Версионирование

Нумерация релизов — **SemVer в обратную сторону:**

- **MAJOR = 0** — всегда.
- **MINOR = релиз-цикл** (0.1 = v0.1 feature set, 0.2 = v0.2 feature set).
- **PATCH = bug-fix / security-fix внутри цикла.**

| Версия | Что в неё входит |
|---|---|
| **v0.0.x** | Phase 0 / 0+ / 0b / 0a — backport passphrase, CI setup, README, KAT-харнесс. Pre-public API. |
| **v0.1** | Phase 1–10: полный v1 feature set. Первый публичный релиз под YSAL-1.0. |
| **v0.2** | Phase 11–15: release workflow, KAT-векторы, SegWit/Taproot, PSBT, multi-sig. Отдельный feature-cycle; Lightning исключён полностью (см. «Отклонённые предложения»). Статус: feature set завершён (2026-09-04, yubtc `9d56ecc`, yubtc-python `8995d9c`); стабильный тег v0.2.0 — после снятия суффикса `-rc.1` (см. TODO.md). |

Правила:

- **YSAL-1.0** — собственное имя лицензии, не привязано к MAJOR-номеру
  релиза. При версионировании не меняется (см. `LICENSE`).
- Phase-имена (Phase 0 / 0+ / 0b / 0a и далее) — внутренние метки
  работ; пользовательские версии начинаются с v0.1.

### Релизная политика

- Релизы собирает `.github/workflows/release.yml` по тегу `v*` —
  единый пайплайн CLI + Android (решение владельца 2026-09-05:
  `android.yml` слит в `release.yml`, Android-проверки — только на
  release-тегах). Джобы и артефакты — таблица «CI workflows» выше.
- **Prerelease-конвенция:** тег, содержащий `-`
  (`contains(ref_name, '-')`), публикуется как GitHub prerelease
  (например, `v0.2.0-rc.1`).

## Принятые решения

Нумерация сквозная, с пропусками: удалённые записи больше не связывают
текущее поведение (история — в git); оставшиеся номера — стабильные
якоря для ссылок из кода и документов, не перенумеровываются.

| # | Вопрос | Решение |
|---|---|---|
| 1 | `bin2privkey` clamp (X25519-style) | **Сохранить только для `yubtc_cascade`; для `pbkdf2`/`argon2id`/`scrypt` пропускать.** yubtc_cascade — собственный KDF, clamp там безвреден и сохраняет bit-for-bit совместимость с pre-passphrase кошельками. Для pbkdf2 clamp искажает секрет и ломает BIP-39-совместимость с Trezor/Ledger/Electrum. Argon2id/scrypt — yubtc-only режимы (нет BIP-39 совместимости в принципе), но clamp для единообразия тоже пропускаем. |
| 2 | Лицензия | **YBTC Limited Source-Available License v1 (YSAL-1.0).** Personal use + private sharing allowed. Создание продуктов (включая бесплатных) запрещено. Licensor оставляет коммерческие права и dual-licensing. См. `LICENSE`. |
| 4 | Web-порт (WASM) | **Out of scope always.** См. «Безопасность: что мы НЕ делаем» ниже. |
| 5 | Tor support | **Out of scope always.** См. «Безопасность: что мы НЕ делаем» ниже. |
| 8 | Lightning Network | **Исключено полностью** (решение 2026-09-02): LN-фонды живут в канальном стейте, а не в ключах — несовместимо со stateless-архитектурой. Развёрнутое обоснование — «Отклонённые предложения → Lightning Network». |
| 10 | Multi-account BIP-44 walks | **Out of scope** — только `account=0`, `chain=0`. Полный обход O(N×M) несовместим с no-storage моделью. |
| 12 | Coin Control UI (выбор UTXO) | **In scope** — пользователь может pre-select UTXO перед подписанием. Multi-source: `WalletHandle` exposes `all_unspent` (eager, Android) и `select_inputs_until` (lazy, CLI/Python parity). UTXO идентифицируется `(nonce, txid, vout)`. |
| 13 | Hardware wallet integration | **Out of scope always.** |

## Безопасность: что мы НЕ делаем (out of scope always)

- ❌ Hardware wallet integration (Ledger, Trezor).
- ❌ Tor support (включая SOCKS5-proxy режим).
- ❌ WASM browser wallet.
- ❌ **Lightning Network** — исключён полностью (решение владельца
  2026-09-02: LN-фонды живут в канальном стейте, а не в ключах —
  несовместимо со stateless-архитектурой). Развёрнутое обоснование —
  «Отклонённые предложения → Lightning Network».

## Отклонённые предложения

- 📋 **Compose UI tests на эмуляторе (`connectedAndroidTest`).** Текущая
  Compose-ветка покрыта только статическим review и ручной сборкой
  APK; screen-level flows (Send → UTXO picker → Confirm → Broadcast)
  не прогоняются автоматизированно. Полная реализация потребует:

  1. Извлечь `WalletEngine` интерфейс как seam между
     `YubtcViewModel` и UniFFI (`WalletHandle` + `uniffi.yubtc_core.*`),
     чтобы тесты могли подсунуть фейковый движок без загрузки
     `.so`.
  2. Добавить зависимости в `android/app/build.gradle.kts`:
     `androidx.compose.ui:ui-test-junit4`,
     `androidx.compose.ui:ui-test-manifest`,
     `com.github.takahirom.roborazzi` (или классический
     Compose screenshot-тест) для визуальной регрессии.
  3. Написать smoke-сценарии: переход Home → Send → utxo_picker →
     back → Confirm, ввод адреса/amount/fee, проверка
     `errorMessage` при невалидном amount, BIP-21 QR при наличии
     `initialAmountBtc`.
    4. Подключить эмулятор-джоб в `.github/workflows/release.yml`
       (matrix: API 30 + API 34) с шагами
      `create-android-emulator`, `./gradlew connectedDebugAndroidTest`.
   5. Кэшировать AVD-образы через `reactivecircus/android-emulator-runner`.

  Объём: новый интерфейс ~8 методов, фейк-движок ~100 строк,
  4–6 Compose-сценариев ~300 строк, новый CI-джоб. Затраты на
  CI: +6–10 мин на запуск эмулятора per ABI. Оправдано когда
  Compose-ветка стабилизируется и ручная сборка APK перестанет
  быть дешёвым валидатором.

- 📋 **Live testnet E2E.** Smoke-сценарии против
  реальных backend'ов (blockchain.info / mempool.space / blockstream
  в testnet-режиме): деривация адреса на свежем seed, проверка
  `balance == 0`, опционально — отправка копеечной tx с faucet и
  ожидание confirmation. Покрытие: регрессии на стороне backend'а
  (изменение формата ответа, новые rate-limits, перенос эндпоинтов).

  Почему не в CI:
  - CI-флаки: внешние сервисы меняются без предупреждения, ломает
    master-build.
  - Стоимость: round-trip 30–60 с + ожидание confirmation 10+ мин.
  - Не воспроизводится локально за корпоративным firewall.
  - Testnet ≠ mainnet: dust threshold, fee market, genesis — другие.

  Если потребуется:
  - ENV-gate `YUBTC_LIVE_TESTNET=1` (по умолчанию выключен).
  - CLI-флаг `--network testnet` (`uniffi.yubtc_core::set_backend`
    с testnet-вариантом) либо новый `Network` enum.
  - Python harness `tests/test_live_testnet.py` + 3 smoke-проверки.
  - Android-часть ждёт разблокировки Compose UI tests.

  До этого момента network-уровень покрывается Wiremock-моками в
  unit-тестах `net/`; регрессии формата ловятся только ручным
  QA на mainnet.

### Lightning Network — исключено полностью (решение 2026-09-02)

Lightning исключён из проекта целиком, без планов на какую-либо
будущую версию (решение #8).

1. **Конфликт со stateless-архитектурой.** yubtc stateless by
   design: ключи деривируются из seed на каждый запуск, ничего не
   персистится (wipe-on-lock). Фонды в LN живут в **канальном
   стейте, а не в ключах**: per-channel commitment-цепочки,
   revocation-секреты, funding outpoint'ы, открытые HTLC,
   CLTV-дедлайны, peer-session — из seed не выводится ничего из
   этого. Восстановленный seed без стейта не отличит устаревший
   commitment от актуального, не сможет реталиировать, потеряет
   in-flight HTLC. В LN seed ≠ контроль — в отличие от on-chain.
2. **Требование постоянного онлайна.** Окна justice/retaliation
   (CSV, часы–недели) требуют watcher'а 24/7 или интеграции с
   watchtower — дополнительный BOLT-компонент и постоянно висящий
   фоновый процесс; оба несовместимы с консольным инструментом,
   который живёт от запуска до запуска и стирает стейт.
3. **Объём и масса.** BOLT 1–11 — отдельный стек протоколов
   (gossip-роутинг BOLT-7, onion-сообщения, краевые случаи
   commitment-трансформаций); реализация с нуля — person-years.
   Встраивание готового движка (класс ldk-node) добавляет
   third-party trust/bug-поверхность и всё равно требует
   персистентного стора; thin client к внешней ноде (lnd/gRPC)
   превращает yubtc во frontend и обесценивает сам порт.
4. **Следствие.** Деривация node-ключа из seed (SLIP-0212
   `m/9737'`) технически тривиальна, но при этом решении
   бессмысленна — она решает node identity, а не канальный стейт.

## См. также

- `README.md` — quick start, статусы работ (Status).
- `specs/UI.md` — спецификация Compose-экранов (элементы, переходы, state-contract, persistence boundaries).
- `../yubtc-python/` — оригинал на Python.
- Python-конвенции зеркала (kwargs-only, 100% line + branch
  coverage, `flake8 --max-line-length=120`) — см. `CONTRIBUTING.md`
  («Зеркало yubtc-python: конвенции»).
