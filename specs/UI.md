# yubtc Android — UI reference

Справочник по Compose-слою `android/app/src/main/java/io/yubtc/wallet/`.
Описывает экраны, элементы управления, граф переходов и контракт
каждого экрана с `YubtcViewModel`. Стиль: «что есть на экране» +
«куда ведёт каждая кнопка» + «какие поля стейта она трогает».

## Архитектура слоя

```
MainActivity
├── ProcessLifecycleOwner ──► LockScheduler         (data/)
└── setContent {
        YubtcTheme {
            YubtcViewModel(viewModel(factory = YubtcViewModelFactory(this)))
            YubtcNavHost(vm)
        }
    }
```

- `YubtcViewModel` — единственный источник правды (один
  `StateFlow<YubtcState>`). Экраны stateless: получают колбэки,
  читают state через `collectAsState()` в `YubtcNavHost`.
- `YubtcNavHost` владеет `NavHostController` и graph'ом из девяти
  destinations (см. ниже). Status-driven navigation: `Locked ⇄
  Loaded` переключает `passphrase ⇄ home`.
- `MainActivity` создаёт `appScope = CoroutineScope(SupervisorJob())`,
  подписывает `LockScheduler` на `ProcessLifecycleOwner.get()` и
  через `LaunchedEffect(vm)` связывает `vm::lock` с планировщиком.

## Граф переходов

```
                    ┌──────────────┐
        cold launch │ passphrase   │  Locked (start)
                    └──────┬───────┘
                  Unlock   │
                            ▼
                     ┌──────────────┐
                     │ home         │  Loaded
                     └──┬─────┬─────┘
            ┌──────────┘     └──────────┐
            ▼              ▼             ▼
       ┌─────────┐    ┌──────────┐   ┌──────────┐
       │ send    │    │ receive  │   │ settings │
       └────┬────┘    └──────────┘   └────┬─────┘
            │           ▲                   │
            │ Request payment (amount?)    │
            │           │                   │
            ▼           │                   │
       ┌───────────┐    │                   │
       │ utxo_     │    │                   │
       │ picker    │    │                   │
       └─────┬─────┘    │                   │
             │ back     │                   │
             ▼          │                   │
       ┌─────────┐      │                   │
       │ send    │──────┘                   │
       └────┬────┘                          │
            │ lastTx != null                │
            ▼                               │
       ┌─────────┐                          │
       │ confirm │                          │
       └────┬────┘                          │
            │ back → clearLastTx + pop      │
            ▼                               │
        (home) ─────────────────────────────┘
                │        │
   Ms create ───┘        └─── Ms send
                ▼              ▼
        ┌────────────┐  ┌────────────┐
        │ ms_create  │  │ ms_send    │
        └────────────┘  └────┬───────┘
                             │ фазы form → built →
                             │ awaiting → imported →
                             │ broadcast — data-driven
                             │ внутри одного destination
                             └── (onBack → pop)
```

`receive` — destination с опциональным query-аргументом
`?amount=<btc>`. Home ходит на bare `receive`; из Send доступен
pre-filled через «Request this amount instead». `Lock` → `vm.lock()`
→ status Locked → `passphrase` (первый `LaunchedEffect`).

`ms_create` / `ms_send` — destinations Phase 15 (multi-sig), дети
home. Обе формы живут в стейте `YubtcState` (`ms*`-поля), поэтому
back-стек не хранит черновики: возврат на home и повторный вход
сохраняет введённые N/M/ключи, пока экран в композиции. Фазы
`ms_send` — data-driven (`state.msPhase`), навигация внутри
destination не происходит.

## Status-driven навигация

`YubtcNavHost` имеет два `LaunchedEffect`:

1. На `state.status` — переход `Locked ⇄ Loaded` между
   `passphrase` и `home`. Использует `popUpTo(0) { inclusive = true }`
   чтобы back stack не накапливал промежуточные экраны.
2. На `state.lastTx` — Send → Confirm. Срабатывает только если
   текущий destination `send` или `utxo_picker`, чтобы случайный
   rebuild не телепортировал пользователя.

## LockScheduler

Не экран, но важная UI-механика. Смонтирован в `MainActivity`:

- На `ON_STOP` стартует coroutine с `delay(idleMinutes * 60_000)`.
  Перед вызовом lock перепроверяет `wipeOnIdle` (защита от race
  между тапом toggle и истечением таймера).
- На `ON_START` отменяет запланированный wipe.
- При срабатывании зовёт `vm::lock()` — это сбрасывает
  `state.status` в `Locked`, что триггерит первый `LaunchedEffect`
  и перекидывает на `passphrase`.

Default: `wipeOnIdle = true`, `idleMinutes = 5`. Настройка в
`SharedPrefsSettingsRepository` (не секрет, plain prefs).

## Экраны

Все экраны лежат в `ui/screens/`, принимают колбэки + state и
полностью stateless относительно VM. Один файл — один `@Composable`.

### passphrase (`PassphraseScreen.kt:73`)

Первый экран на cold launch. Locked-состояние.

**Элементы:**
- Заголовок `yubtc` + подсказка «Enter your BIP-39 seed and passphrase».
- `OutlinedTextField` seed (multi-line, без auto-correct, без trim при
  unlock — `seed.trim()` в unlock-кнопке).
- `OutlinedTextField` passphrase (single-line, `PasswordVisualTransformation`,
  `KeyboardType.Password`). Passphrase намеренно не тримится — BIP-39
  допускает пробелы в начале/конце.
- Row кнопок `Unlock` (enabled когда `seed.isNotBlank()`) + `Generate`.
- `Card` с превью сгенерированного seed (когда `generatedSeed != null`):
  три кнопки `Copy` (clipboard), `Use` (заполняет поле seed), `Dismiss`.
- `errorMessage` снизу красным.
- Предупреждение энтропии: при оценке `bits < 128` (R-6 spec.md) —
  карточка «Low entropy» с кнопками `Continue` / `Edit`;
  предупреждение не блокирует unlock.

**Переходы:**
- `Unlock` → `vm.unlock(seed.trim(), passphrase)`. Status → Loaded,
  `LaunchedEffect(state.status)` перекидывает на `home`.
- Unlock при `bits < 128` → предупреждение «Low entropy»: `Continue`
  повторяет `vm.unlock(...)`, `Edit` закрывает предупреждение и
  возвращает к вводу.
- `Generate` → `vm.generateSeed(12u)`. Результат в `state.generatedSeed`.
- `Use` → `seed = generatedSeed; vm.dismissGeneratedSeed()`.
- `Dismiss` → `vm.dismissGeneratedSeed()`.

**Контракт:**
- Seed не персистится; пустой passphrase → legacy `Yubtc` KDF
  (bit-for-bit совместим со старыми seed'ами).
- Режим приёма seed: permissive по умолчанию (любая непустая фраза,
  R-1 spec.md); `strictBip39 = true` добавляет блокирующий BIP-39
  parse + entropy floor (R-4), ошибка — в `state.errorMessage`.
  Пустая фраза — ошибка в обоих режимах (R-2). Предупреждение
  энтропии — неблокирующее в обоих режимах (R-6).
- Ошибка `YubtcException` из UniFFI ложится в `state.errorMessage`
  и не сбрасывает seed/passphrase — пользователь правит и жмёт
  Unlock снова.

### home (`HomeScreen.kt:51`)

Landing-экран при Loaded.

**Элементы:**
- Заголовок «Wallet».
- `Card` с балансом (`finalBalanceSat` → `satoshiToBtc`), total received
  и `n_tx`. Пока `addressInfo == null` показывает «—».
- Адрес моноширинным шрифтом.
- Row `Send` / `Receive`.
- Row `Settings` / `Lock`.
- Кнопка `Refresh balance`.

**Переходы:**
- `LaunchedEffect(Unit)` → `vm.refreshAll()` на первом compose.
- `Send` / `Receive` / `Settings` → `navController.navigate(<route>)`.
- `Lock` → `vm.lock()`. Status → Locked → `passphrase`.
- `Refresh balance` → `vm.refreshAll()`.

### send (`SendScreen.kt:63`)

Форма отправки. Содержит UTXO picker как отдельный destination.

**Элементы:**
- Заголовок «Send», под ним `Cashback to: <addr>`.
- `OutlinedTextField` destination (`KeyboardCapitalization.None`,
  auto-correct off).
- Row: `OutlinedTextField` amount + Switch «Send max» (включает drain,
  amount становится `null`).
- Slider fee rate 1–20 sat/vB; ниже `Confirmations` chip-group (`0`/`1`/`6`,
  `0` показан как «any»).
- `OutlinedButton` «Pick inputs: $selectedCount selected».
- `Button` «Build transaction».
- `OutlinedButton` «Request this amount instead» (T4).
- `OutlinedButton` «Back».

**Переходы:**
- `Pick inputs` → `navController.navigate("utxo_picker")`.
- `Build transaction` → `vm.makeTransactionMultiFromBtc(...)`. Результат
  в `state.lastTx` → навигация на `confirm`.
- `Request this amount instead` → `navController.navigate("receive?amount=$amt")`
  (или bare `receive` при `sendMax`/`empty`).
- `Back` → `popBackStack()`.

**Контракт:**
- `amountText` пуст → amount = null → core вернёт ошибку «amount
  required» в `state.errorMessage` (не uncaught exception).
- Disabled state кнопки Build — `dst.isNotBlank()`. Другие валидации
  делает UniFFI-слой.

### utxo_picker (`UtxoPickerScreen.kt:55`)

Coin Control. Mirrors CLI `send -i` TUI.

**Элементы:**
- Заголовок «Pick inputs» + счётчик «$selectedSize / $total selected».
- Row `All` / `Auto` / `None`.
- `LazyColumn` карточек: чекбокс + `<nonce># · <txid-prefix>:<vout>` +
  `<amount> BTC · <conf> conf`.
- Empty state (`unspent.isEmpty()`) — карточка с «No UTXOs available at
  this confirmations depth».
- Row `Cancel` / `Confirm` (Confirm disabled при пустом выборе).

**Переходы:**
- `LaunchedEffect(Unit)` → `vm.allUnspent()` (обновляет кэш).
- `All` → `vm.selectAllUtxos()`.
- `Auto` → `vm.autoPick(null)` (drain).
- `None` → `vm.clearUtxoSelection()`.
- Tap по карточке → `vm.toggleUtxo(u)`.
- `Confirm` / `Cancel` → `popBackStack()` к send.

**Контракт:**
- `UtxoWithNonce` хранится в `state.selectedUtxos: Set<UtxoWithNonce>` —
  тот же ключ используется в `state.unspent`. Set identity = equality.
- При возврате на send видно обновлённый счётчик.

### confirm (`ConfirmScreen.kt:39`)

Просмотр собранной tx перед broadcast.

**Элементы:**
- Заголовок «Confirm».
- `Card` со статами: `Amount` / `Fee` / `Cashback` / `Txid` / `Network
  txid` (последний появляется после broadcast).
- `Card` с raw hex (полный `tx.txHex`).
- Row `Back` / `Broadcast` (или `Broadcasted ✓`).

**Переходы:**
- `Back` → `vm.clearLastTx(); popBackStack(route="home")`. Сброс
  `lastTx` обязателен — иначе следующая сборка на send не
  сработает.
- `Broadcast` → `vm.broadcast(tx.txHex)`. Результат в
  `state.lastTxid`.

### ms_create (`MsCreateScreen.kt:65`)

Multi-sig quorum address (spec.md «Multi-sig → Принято
(2026-09-02): полный surface»; селектор форм трёх форм кворума —
«Multi-sig», ОВ-19). Офлайн-форма:
pure-функция FFI, сети нет, при watch-only не запрашивается и seed.

**Элементы:**
- Заголовок «Multisig create», подзаголовок «Quorum address (m-of-n,
  BIP-67 sorted)».
- Селектор формы (v0.3): chip-group `P2SH (3…)` / `P2WSH (bc1q…)` /
  `P2TR (bc1p…)`; default `p2sh` (документированное spec-решение).
  Выбор меняет адресную кодировку, а для p2tr — и сам скрипт
  (CHECKSIGADD-тапскрипт вместо CHECKMULTISIG-redeem) и кодировку
  ключей (R-MS-10); под селектором — подсказка `MsQuorum.formHint`.
- `OutlinedTextField` N + `OutlinedTextField` M — **обязательные
  поля без значений по умолчанию** (R-MS-1): оба стартуют пустыми;
  isError, если введено нечисловое значение.
- Switch «Our key»: off — watch-only create (полностью офлайн, без
  seed); on — появляется поле `Nonce (our key derivation)`, наш
  legacy-ключ деривируется на `-n` и дописывается в кворум
  (R-MS-6, ОВ-10).
- Редактор списка ключей: строки «Key i (<кодировка>)» + «✕»
  (remove), кнопка `Add key`; кодировка в подписи строки следует
  форме (`MsQuorum.keyFieldLabel`: «compressed hex pubkey» для
  p2sh/p2wsh, «x-only hex pubkey» для p2tr). Per-key валидация при
  вводе (`MsQuorum.keyError(hex, form)`, R-MS-3/R-MS-10: пустое /
  66 hex с префиксом `02`/`03` / hex — либо 64 hex x-only для
  p2tr); дубликаты подсвечиваются (`MsQuorum.duplicateIndexes`,
  case-insensitive) с подписью «Duplicate keys in the quorum».
  При own key ON требуется ровно N−1 косайнерских строк, иначе
  «Key count must equal N».
- `Button` «Create quorum address» (enabled когда N и M введены,
  клиентская проверка `1 ≤ M ≤ N ≤ 15` из `MsQuorum.quorumError`
  прошла — локальный эквивалент `MsError::QuorumBounds`, — число
  ключей сходится, формат и дубликаты в порядке).
- Result-`Card` (когда `state.msAddress != null`): QR адреса 256×256
  (`qrcode-kotlin`, как ReceiveScreen), строки `Address` / `Redeem
  script` (hex; для p2tr — сам тапскрипт: имя поля
  `redeemScriptHex` стабильно, байты другие); для p2tr
  дополнительно `Internal key (NUMS)` и `Control block` (33 байта,
  hex — witness-материал траты p2tr), кнопка `Copy address`
  (clipboard, label «yubtc quorum address»).
- `OutlinedButton` «Back»; ошибки — `errorMessage` красным.

**Переходы:**
- `Create quorum address` → `vm.msCreateAddress(n, m, keys, nonce,
  form)`. `nonce = null` при watch-only. Результат в
  `state.msAddress` (вся форма — screen-local Compose state,
  выбранный chip переживает повторный create).
- Кнопка create недоступна, пока N или M не введены (R-MS-1 — нет
  значения по умолчанию, никогда).
- `Back` → `popBackStack()` к home.

**Контракт:**
- Валидация двухуровневая: `MsQuorum` (data/, pure Kotlin, покрыт
  JVM-тестами) даёт field-level ошибки до запроса — кодировка ключей
  следует форме (R-MS-10); авторитетный отказ —
  `MsError::QuorumBounds`/`DuplicateKey`/`KeyCountMismatch`/
  `InvalidKeyEncoding` из FFI, ложится в `state.errorMessage`.
- Ошибка не сбрасывает форму — пользователь правит ввод и жмёт
  create снова.
- Адрес фиксирован кортежем (N, M, множество ключей) в выбранной
  форме (ОВ-13): один и тот же ввод даёт один и тот же адрес
  независимо от порядка строк (BIP-67 sort на стороне core, R-MS-4;
  для p2tr сортировка по x-only байтам).

### ms_send (`MsSendScreen.kt:85`)

Multi-sig трата (Phase 15). Контракт экрана — **излучить PSBT и
принять PSBT назад**; раунды подписания косайнеров экраном не
оркестрируются (out-of-band, транспорт — base64-PSBT). State
machine (data-driven, `state.msPhase`):

```
form → built → awaiting (out-of-band раунды) → imported → broadcast
```

Все фазы рендерятся внутри одного destination `ms_send`; переходы —
только через VM-мутации ([MsSendFlow], [YubtcViewModel]);
отказ FFI не меняет фазу — ошибка в `state.errorMessage`, состояние
сохранено. «Back to form» доступен на любом шаге без потери
введённых N/M/ключей (они — screen-local Compose state).

**Элементы (общие):**
- Заголовок «Multisig send» + подпись контракта; индикатор `Phase:
  <phase>`.
- `OutlinedButton` «Back» (popBackStack к home) и `errorMessage`
  внизу — на всех фазах.

**Фаза form:**
- Кворум-редактор: те же N/M (без дефолтов, R-MS-1), Switch «Our
  key» + nonce, редактор ключей, что на `ms_create` — включая
  трёхсегментный селектор формы (`P2SH (3…)` / `P2WSH (bc1q…)` /
  `P2TR (bc1p…)`, default `p2sh`): выбор задаёт и адрес UTXO
  кворума, и кодировку ключей (R-MS-10), и выбор переживает фазовые
  переходы вместе с остальным вводом.
- Spend-поля с семантикой SendScreen: destination, amount (BTC —
  обязателен, drain-режима у кворумной траты нет), slider fee rate
  1–20 sat/vB, chip-group Confirmations (`0`/`1`/`6`).
- Coin Control над адресом кворума (паттерн `utxo_picker`, ОВ-13):
  строка «Quorum UTXOs: X / Y selected» + кнопка `Fetch`
  (`vm.msFetchUnspent(...)` — прямой `get_utxos` адреса кворума с
  фильтром confirmations; nonce у всех строк — 0-сентинел);
  список карточек с чекбоксами (bounded-height LazyColumn); `All` /
  `None`. Пустое состояние — карточка «No UTXOs fetched yet…».
- `Button` «Build PSBT» — enabled только при полном кворуме,
  `ownKey == true` (watch-only кворум не тратится:
  `NotAParticipant` — клиентская отсечка в VM до FFI) и
  непустых destination/amount.

**Фаза built** (после `ms_build_psbt`; свой ключ уже подписал —
Creator + Signer за один шаг, ОВ-12):
- `Card` со статами: PSBT txid, Inputs, Outputs, Fee
  (`state.msBuiltFeeSat`), Our partial sigs. Fee/vsize приходят из
  core: для p2tr-входов оценка witness — R-MS-11 (слоты подписей +
  тапскрипт + control block), отображение то же.
- QR PSBT (256×256) — когда контейнер влезает; иначе подпись «PSBT
  too large for a QR — use Copy instead».
- `Card` с полным base64-PSBT + кнопка `Copy PSBT (base64)`
  (label «yubtc psbt»).
- `Button` «Hand off to cosigners» → фаза awaiting.

**Фаза awaiting:**
- Подсказка «Waiting for cosigners…», поле `Finalized PSBT
  (base64)` (paste-импорт combined+finalized контейнера).
- `Button` `Import PSBT` → `vm.msImportPsbt` (`psbt_decode`);
  успех → фаза imported. Битый base64 — ошибка декода в
  `errorMessage`, состояние не сбрасывается.

**Фаза imported:**
- `Card`-превью декодированного финализированного контейнера:
  PSBT txid, Inputs, Outputs, Fee («— (no UTXO data)», когда поле
  отсутствует), Finalized inputs.
- `Button` `Extract & broadcast` → `vm.msBroadcastFinalized()`
  (`psbt_extract` + `broadcast`) → фаза broadcast.
  Не-finalized / чужой кворум — авторитетный отказ FFI на этом
  шаге, в `errorMessage`, состояние (фаза imported) сохранено.

**Фаза broadcast:** `Card` «Broadcasted ✓» + Network txid
(`state.msFinalTxid`); `Button` «New spend» → назад на form
(артефакты флоу сброшены, введённый кворум остаётся).

**Контракт:**
- Переиспользует state-контракт Send/UtxoPicker/Confirm: destination/
  amount/fee/confirmations — та же семантика, что SendScreen; выбор
  входов — выделенный ms-набор (`msUnspent`/`msSelectedUtxos`), не
  пересекающийся с личным `unspent`/`selectedUtxos` (кворумный
  адрес не участвует в nonce-walk, ОВ-13).
- Числовые поля N/M/keys и выбранный form живут на экране и
  проходят фазовые переходы без изменений — «назад на любом шаге —
  без потери введённых N/M/ключей до успешного broadcast» (spec).
  State machine ([MsSendFlow]) form-агностична: ни одна фаза не
  читает форму — форма уходит только параметром FFI-вызова
  (`ms_build_psbt`, `ms_fetch_unspent`), так что третья форма
  (p2tr) не добавляет состояний и переходов (ОВ-19).
- Cashback траты — на адрес кворума (решает core, не экран).
- Все FFI-вызовы идут через `viewModelScope.launch` c
  `catch (YubtcException)` → `state.errorMessage` — без uncaught
  exception'ов на main thread.

### receive (`ReceiveScreen.kt:59`)

Показывает BIP-21 QR + monospace URI для копирования.

**Элементы:**
- Заголовок «Receive».
- QR-код 256×256 (рендерится через `qrcode-kotlin`, no Google Play).
- Текстовый URI (`bip21Text ?? address ?? "(wallet not loaded)"`).
- `OutlinedTextField` Amount (BTC, optional) с валидацией
  `Bip21Uri.AMOUNT_PATTERN`, isError при нарушении.
- `OutlinedTextField` Label (optional).
- `OutlinedTextField` Message (optional).
- `OutlinedButton` «Copy URI» — копирует URI под label
  «yubtc bip-21».
- `OutlinedButton` «Back».

**Переходы:**
- `Copy URI` enabled когда `bip21Text != null`.
- `Back` → `popBackStack()`.

**Контракт:**
- При вызове из Send с `initialAmountBtc` поле amount предзаполнено.
- QR и «Copy URI» гейтятся `isAmountValid` — невалидный amount не
  даёт ни QR, ни копирования (см. `Bip21Uri.AMOUNT_PATTERN`).
- Decimal separator всегда `.`, независимо от device locale
  (`Bip21Uri.toUriString()` использует строковый builder).

### settings (`SettingsScreen.kt:42`)

**Элементы:**
- Заголовок «Settings».
- `Card` Network backend: chip-group `blockchain.info` / `blockstream`
  / `mempool.space` (выделен активный).
- `Card` Privacy: Switch «Wipe wallet when leaving the app» + chip-group
  «1 min» / «5 min» / «15 min».
- `Card` Seed: Switch «Strict BIP-39 validation» (настройка
  `strictBip39`, default off).
- `Button` «Lock wallet».
- `OutlinedButton` «Back».

**Переходы:**
- Тап chip backend → `vm.setBackend(name)`.
- Switch toggle → `vm.setWipeOnIdle(enabled)`.
- Тап chip delay → `vm.setIdleMinutes(minutes)`.
- Switch «Strict BIP-39» → `vm.setStrictBip39(enabled)`.
- `Lock wallet` → `vm.lock()`.
- `Back` → `popBackStack()`.

**Контракт:**
- Список backend'ов — локальный mirror `core/src/net::get_backend`.
  Тап по уже активному — no-op.
- Delay chip'ы — локальный mirror `IDLE_CHOICES_MIN`. UI не даёт
  выбрать значение вне 1/5/15; репозиторий всё равно clamp'ит.
- `strictBip39` — не секрет; хранится рядом с `wipeOnIdle`
  (`SharedPrefsSettingsRepository`). Влияет на приём seed на
  passphrase-экране (R-3/R-4 spec.md).

## State — что и где

`YubtcState` (data class) — все поля, которые читают экраны:

| Поле | Кто читает | Кто пишет |
|---|---|---|
| `status` | NavHost, PassphraseScreen (через redirect) | `unlock`, `lock` |
| `address` | Home, Send (cashback), Receive, NavHost | `unlock` |
| `addressInfo` | Home | `refreshAddressInfo`, `refreshAll` |
| `unspent` | Send (cashback fallback), UtxoPicker | `allUnspent`, `refreshAll` |
| `cashbackAddr` | Send | `allUnspent`, `refreshAll` |
| `selectedUtxos` | Send (counter), UtxoPicker | `toggleUtxo`, `selectAllUtxos`, `clearUtxoSelection`, `autoPick` |
| `lastTx` | Confirm, NavHost (nav trigger) | `makeTransactionMulti`, `send` |
| `lastTxid` | Confirm | `broadcast`, `send` |
| `currentBackend` | Settings | `setBackend` |
| `generatedSeed` | PassphraseScreen | `generateSeed`, `dismissGeneratedSeed` |
| `wipeOnIdle` | Settings, LockScheduler | `setWipeOnIdle` |
| `idleMinutes` | Settings, LockScheduler | `setIdleMinutes` |
| `strictBip39` | Settings, passphrase (режим приёма seed) | `setStrictBip39` |
| `lowEntropyWarning` | PassphraseScreen (карточка «Low entropy») | `unlock` (ставит при `bits < 128`), `dismissLowEntropyWarning` |
| `msAddress` | MsCreateScreen (result-`Card`: адрес формы, redeem/tapscript hex, p2tr — internal/control) | `msCreateAddress` |
| `msPhase` | MsSendScreen (индикатор фазы + выбор секции) | `MsSendFlow`-переходы через `msBuildPsbt`, `msMarkAwaiting`, `msImportPsbt`, `msBroadcastFinalized`, `msBackToForm` |
| `msPsbt` | MsSendScreen (фаза built: QR + copy) | `msBuildPsbt` (ставит), `msBackToForm` (сбрасывает) |
| `msPsbtSummary` | MsSendScreen (фаза built: статы) | `msBuildPsbt` (`psbt_decode` результата), `msBackToForm` |
| `msBuiltFeeSat` | MsSendScreen (фаза built: Fee) | `msBuildPsbt`, `msBackToForm` |
| `msImportedPsbt` | — (хранится для extract+broadcast) | `msImportPsbt`, `msBackToForm` |
| `msImportedSummary` | MsSendScreen (фаза imported: превью) | `msImportPsbt` (`psbt_decode` импорта), `msBackToForm` |
| `msFinalTxid` | MsSendScreen (фаза broadcast) | `msBroadcastFinalized`, `msBackToForm` |
| `msUnspent` | MsSendScreen (form: список UTXO кворума) | `msFetchUnspent`, `msSelectAllUtxos` |
| `msSelectedUtxos` | MsSendScreen (form: счётчик выбора) | `msToggleUtxo`, `msSelectAllUtxos`, `msClearUtxoSelection`, `msFetchUnspent` (prune до свежего набора) |
| `errorMessage` | PassphraseScreen, Send, MsCreate, MsSend | любой `catch (YubtcException)` в VM |

Все мутации идут через `viewModelScope.launch { try { ... } catch
(YubtcException) { errorMessage = e.message } }` — никаких uncaught
exception'ов на main thread.

## Persistence границы

Stateless by design (specs/spec.md «Android / uniffi» → «Безопасность»):

- `SharedPrefsSettingsRepository` (`SharedPreferences`) — UI-настройки:
  `wipeOnIdle`, `idleMinutes`, `strictBip39`. Это не секрет.
- `YubtcViewModel.wallet: WalletHandle?` — единственная живая ссылка
  на UniFFI-handle. `onCleared()` зовёт `destroy()`.
- `ProcessLifecycleOwner` wipe → `vm.lock()` → `wallet = null` →
  status → Locked → nav на passphrase. Seed/passphrase **не
  персистятся нигде**.