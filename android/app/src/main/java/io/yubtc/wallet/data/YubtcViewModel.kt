package io.yubtc.wallet.data

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import uniffi.yubtc_core.AddressInfoRecord
import uniffi.yubtc_core.AddrTypeName
import uniffi.yubtc_core.KdfAlgoName
import uniffi.yubtc_core.MsAddressRecord
import uniffi.yubtc_core.MsFormName
import uniffi.yubtc_core.PsbtSummaryRecord
import uniffi.yubtc_core.SelectedSource
import uniffi.yubtc_core.TxResultRecord
import uniffi.yubtc_core.UtxoWithNonce
import uniffi.yubtc_core.WalletHandle
import uniffi.yubtc_core.YubtcException

/**
 * Single source of truth for the wallet screen state.
 *
 * The ViewModel wraps the synchronous UniFFI surface in
 * `viewModelScope.launch { ... }` so the network round-trips stay
 * off the main thread. All public state is exposed as [StateFlow] so
 * Compose can collect it inside `collectAsStateWithLifecycle`.
 *
 * **Wallet lifecycle.** [WalletHandle] is a handle to a JNA-backed
 * Rust object; the VM owns the only live reference for the duration
 * of the process so JNA's reference cleaner can `free` it on
 * disposal. Re-creating the handle invalidates the old one and
 * clears the cached address info / UTXOs.
 *
 * **Multi-source UTXO model.** UTXOs are identified by
 * `(nonce, txid, vout)` — see [UtxoWithNonce]. The
 * [YubtcViewModel.allUnspent] call performs an eager scan to
 * gap-limit, populating [YubtcState.unspent] with every contributing
 * UTXO across every owned address. Build (`[send]`) and Coin Control
 * (`[makeTransactionMulti]`) pass the same set back to
 * `makeTransactionMulti`; the picker uses
 * [UtxoWithNonce] values directly as the `Set` element type so the
 * `nonce` needed by [SelectedSource] is preserved through the
 * navigation.
 *
 * **State transitions.** Status flips to [WalletStatus.Locked] when
 * the handle is cleared and back to [WalletStatus.Loaded] once a
 * seed + passphrase successfully derive a handle. Errors are stored
 * in [errorMessage] and cleared on the next successful operation.
 */
class YubtcViewModel(
    private val settings: SettingsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(
        YubtcState(
            wipeOnIdle = settings.wipeOnIdle,
            idleMinutes = settings.idleMinutes,
            strictBip39 = settings.strictBip39,
            addrType = settings.addrType,
        ),
    )
    val state: StateFlow<YubtcState> = _state.asStateFlow()

    /**
     * Currently bound wallet handle, or `null` when no seed has been
     * unlocked. The JNA cleaner owns the underlying memory; we hold
     * the Kotlin reference only to invoke methods on it.
     */
    private var wallet: WalletHandle? = null

    /**
     * The seed the currently displayed low-entropy warning was
     * computed for. `null` when no warning is pending. Used to
     * distinguish the user's `Continue` (a repeated [unlock] with
     * the same seed confirms past the warning) from a fresh unlock
     * attempt with a different seed.
     */
    private var warnedSeed: String? = null

    /**
     * Toggle the "wipe wallet when leaving the app" setting. The
     * scheduler reads this on every `ON_STOP`, so flipping the
     * switch is enough — there is no separate "arm" step.
     *
     * Disabling cancels any in-flight wipe job: the
     * [LockScheduler.scheduleIfEnabled] re-checks the toggle
     * inside the launched block before firing, so a stale job
     * quietly exits when the new value reads OFF. The VM just
     * persists the new value here — the next lifecycle event
     * sees the updated reading.
     */
    fun setWipeOnIdle(enabled: Boolean) {
        settings.wipeOnIdle = enabled
        _state.value = _state.value.copy(wipeOnIdle = enabled)
    }

    /**
     * Change the auto-wipe idle window. Allowed values are
     * `1`, `5`, `15` minutes; the [SettingsRepository] clamps
     * out-of-range inputs. The next `ON_STOP` event reads the
     * new value via `getIdleMillis()`.
     */
    fun setIdleMinutes(minutes: Int) {
        settings.idleMinutes = minutes
        _state.value = _state.value.copy(idleMinutes = settings.idleMinutes)
    }

    /**
     * Toggle the opt-in strict BIP-39 seed-reception mode (spec.md
     * «Seed policy», R-3). `true` makes the next [unlock] require a
     * full BIP-39 parse plus the C6 entropy floor (blocking, R-4);
     * `false` (the default) keeps the permissive reception (R-1).
     * The warning path (R-6) is unaffected by this toggle.
     */
    fun setStrictBip39(enabled: Boolean) {
        settings.strictBip39 = enabled
        _state.value = _state.value.copy(strictBip39 = enabled)
    }

    /**
     * Change the receive-address form (Phase 13): one of
     * `"legacy"` / `"native"` / `"taproot"` — the values mirrored by
     * the Settings chip group and normalized by the repository.
     * The next [unlock] creates the handle with this type, so
     * Home / Receive display the matching address (`1…` / `bc1q…` /
     * `bc1p…`); an already-unlocked wallet keeps its current handle
     * until it is re-locked, matching how `strictBip39` only affects
     * the next unlock.
     */
    fun setAddrType(value: String) {
        settings.addrType = value
        _state.value = _state.value.copy(addrType = settings.addrType)
    }

    /** Close the «Low entropy» warning (`Edit` button) and return
     *  to input. The next [unlock] re-evaluates the estimate from
     *  scratch — including for the same seed. */
    fun dismissLowEntropyWarning() {
        warnedSeed = null
        _state.value = _state.value.copy(lowEntropyWarning = null)
    }

    /**
     * Open a wallet from a BIP-39 mnemonic + optional passphrase.
     *
     * `nonce` defaults to `0` (matches CLI behaviour). `kdf` is
     * resolved from the passphrase: empty → [KdfAlgoName.YUBTC]
     * (legacy mainnet path), non-empty → [KdfAlgoName.PBKDF2]
     * (BIP-39 standard). The auto-resolution is the same as the
     * CLI's `--kdf auto`.
     *
     * **Seed policy (C8).** Before the handle is created, the seed's
     * entropy estimate is evaluated through the core's
     * `entropyWarning` (R-6, both modes): below 128 estimated bits
     * the «Low entropy» warning is raised — [unlock] returns without
     * unlocking, and repeating the call with the same seed acts as
     * the `Continue` confirmation. The reception mode comes from the
     * `strictBip39` setting: permissive (default, R-1) accepts any
     * non-empty phrase; strict (R-4) adds the blocking BIP-39 parse
     * + entropy floor inside the core constructor, before KDF. The
     * empty phrase always fails with `EmptySeed` (R-2).
     *
     * On success, replaces the current handle and stores the derived
     * address — the receiving address in the `addrType` form
     * (`[SettingsRepository.addrType]`, default `native`): for the
     * BIP-39 `pbkdf2` branch each form is its own BIP-32 purpose
     * leaf (`m/44'…` / `m/84'…` / `m/86'…`). On failure, leaves the
     * existing handle intact and surfaces [YubtcException] in
     * [YubtcState.errorMessage].
     */
    fun unlock(seed: String, passphrase: String, nonce: UInt = 0u) {
        val kdf = if (passphrase.isEmpty()) KdfAlgoName.YUBTC else KdfAlgoName.PBKDF2
        viewModelScope.launch {
            try {
                // R-6: non-blocking low-entropy warning. A repeated
                // unlock with the warned seed is the user's
                // `Continue`; anything else re-evaluates.
                if (_state.value.lowEntropyWarning != null && seed == warnedSeed) {
                    dismissLowEntropyWarning()
                } else {
                    warnedSeed = null
                    val warning = uniffi.yubtc_core.entropyWarning(seed)
                    if (warning != null) {
                        warnedSeed = seed
                        _state.value =
                            _state.value.copy(lowEntropyWarning = warning, errorMessage = null)
                        return@launch
                    }
                }
                val handle = WalletHandle(
                    seed = seed,
                    nonce = nonce,
                    passphrase = passphrase,
                    kdf = kdf,
                    backend = null,
                    strictBip39 = settings.strictBip39,
                    addrType = addrTypeName(settings.addrType),
                )
                val address = handle.receivingAddress()
                wallet = handle
                _state.value = _state.value.copy(
                    status = WalletStatus.Loaded,
                    address = address,
                    errorMessage = null,
                )
            } catch (e: YubtcException) {
                _state.value = _state.value.copy(errorMessage = e.message ?: "unlock failed")
            }
        }
    }

    /**
     * Drop the handle and clear cached state. Safe to call when no
     * handle is held — this is a no-op then. Also evicts the cached
     * scan (per Rust `WalletHandle::lock`).
     *
     * The settings-derived fields (`wipeOnIdle`, `idleMinutes`,
     * `strictBip39`) are re-read from the repository so the fresh
     * state reflects the persisted values instead of the data-class
     * defaults.
     */
    fun lock() {
        wallet?.let { handle ->
            try {
                handle.lock()
            } catch (_: YubtcException) {
                // Lock is best-effort; ignore errors here.
            }
        }
        wallet?.destroy()
        wallet = null
        warnedSeed = null
        _state.value = YubtcState(
            status = WalletStatus.Locked,
            wipeOnIdle = settings.wipeOnIdle,
            idleMinutes = settings.idleMinutes,
            strictBip39 = settings.strictBip39,
            addrType = settings.addrType,
        )
    }

    /**
     * Fetch address info from the current backend. Network call —
     * runs off the main thread via [viewModelScope].
     */
    fun refreshAddressInfo() {
        val handle = wallet ?: return
        viewModelScope.launch {
            try {
                val info: AddressInfoRecord = handle.addressInfo()
                _state.value = _state.value.copy(addressInfo = info, errorMessage = null)
            } catch (e: YubtcException) {
                _state.value = _state.value.copy(errorMessage = e.message ?: "address info failed")
            }
        }
    }

    /**
     * Eager scan to gap-limit: fetches every contributing UTXO at
     * `confirmations` depth across all owned addresses, refreshes
     * [YubtcState.unspent] and [YubtcState.cashbackAddr]. Network
     * call — runs off the main thread via [viewModelScope].
     *
     * Uses the FFI `selectInputsUntil(None, c)` path so the cashback
     * address (gap-limit unused) comes back in the same round-trip
     * as the UTXO set — see the spec's "Data flow (Android)".
     */
    fun allUnspent(confirmations: UInt = 6u) {
        val handle = wallet ?: return
        viewModelScope.launch {
            try {
                val result = handle.selectInputsUntil(null, confirmations)
                _state.value = _state.value.copy(
                    unspent = result.utxos,
                    cashbackAddr = result.cashbackAddr,
                    errorMessage = null,
                )
            } catch (e: YubtcException) {
                _state.value = _state.value.copy(errorMessage = e.message ?: "unspent fetch failed")
            }
        }
    }

    /**
     * Refresh both [refreshAddressInfo] and [allUnspent] in sequence.
     * The Home screen wires this to its refresh button.
     */
    fun refreshAll(confirmations: UInt = 6u) {
        val handle = wallet ?: return
        viewModelScope.launch {
            try {
                val info = handle.addressInfo()
                val scan = handle.selectInputsUntil(null, confirmations)
                _state.value = _state.value.copy(
                    addressInfo = info,
                    unspent = scan.utxos,
                    cashbackAddr = scan.cashbackAddr,
                    errorMessage = null,
                )
            } catch (e: YubtcException) {
                _state.value = _state.value.copy(errorMessage = e.message ?: "refresh failed")
            }
        }
    }

    /**
     * Build a transaction from the cached [YubtcState.unspent] using
     * the user's manual picker selection. Mirrors the CLI
     * `makeTransactionMulti` flow: caller passes the full UTXO set
     * the picker sees, the selection subset, and the cashback
     * address. The cashback is the gap-limit unused address from the
     * most recent scan, or `state.address` as a fallback when the
     * scan was empty.
     *
     * `feeSat == 0UL` makes the core run its fee loop using
     * `feekbSat` as the target rate (matches CLI `send` default).
     * `amountSat == null` drains the wallet. The `confirmations`
     * filter is already applied at scan time — the UTXO list in
     * [YubtcState.unspent] reflects whatever depth the user
     * selected on the picker screen. On success, stores the result
     * in [YubtcState.lastTx]; on broadcast rejection, leaves the
     * built (but unsent) tx in [YubtcState.lastTx] and surfaces the
     * error.
     */
    fun makeTransactionMulti(
        dst: String,
        amountSat: ULong?,
        feekbSat: ULong,
        feeSat: ULong,
        selected: List<SelectedSource>,
    ) {
        val handle = wallet ?: run {
            _state.value = _state.value.copy(errorMessage = "wallet locked")
            return
        }
        viewModelScope.launch {
            try {
                val utxos = _state.value.unspent
                val cashback = _state.value.cashbackAddr ?: _state.value.address ?: ""
                if (cashback.isEmpty()) {
                    _state.value = _state.value.copy(errorMessage = "no cashback address")
                    return@launch
                }
                val result: TxResultRecord = handle.makeTransactionMulti(
                    utxos = utxos,
                    selected = selected,
                    cashbackAddr = cashback,
                    dst = dst,
                    amountSat = amountSat,
                    feekbSat = feekbSat,
                    feeSat = feeSat,
                )
                _state.value = _state.value.copy(
                    lastTx = result,
                    lastTxid = null,
                    errorMessage = null,
                )
            } catch (e: YubtcException) {
                _state.value = _state.value.copy(errorMessage = e.message ?: "send failed")
            }
        }
    }

    /**
     * Same as [makeTransactionMulti] but takes `amountBtc` as a
     * string and parses via `btcToSatoshi` inside the coroutine —
     * so a parse error surfaces as [YubtcState.errorMessage]
     * instead of an uncaught exception on the UI thread.
     *
     * `amountBtc == null` → drain; otherwise the trimmed string is
     * fed to `btcToSatoshi` (e.g. `"0.001"`). `confirmations` is
     * kept in the signature so the Send screen can pass its
     * filter through unchanged even though the build itself is
     * pure — the actual filter is applied at the scan layer.
     */
    fun makeTransactionMultiFromBtc(
        dst: String,
        amountBtc: String?,
        feekbSat: ULong,
        feeSat: ULong,
        confirmations: UInt,
        selected: List<SelectedSource>,
    ) {
        viewModelScope.launch {
            try {
                val amountSat: ULong? = if (amountBtc == null) {
                    null
                } else {
                    uniffi.yubtc_core.btcToSatoshi(amountBtc.trim())
                }
                makeTransactionMulti(
                    dst = dst,
                    amountSat = amountSat,
                    feekbSat = feekbSat,
                    feeSat = feeSat,
                    selected = selected,
                )
            } catch (e: YubtcException) {
                _state.value = _state.value.copy(errorMessage = e.message ?: "amount parse failed")
            }
        }
    }

    /**
     * Build + broadcast a transaction in one step. Convenience for
     * the Send screen's "Build & broadcast" path; the underlying
     * state machine is identical to [makeTransactionMulti]. The
     * `confirmations` parameter is unused at build time but kept
     * for symmetry with [makeTransactionMultiFromBtc] — the actual
     * filter is applied at the scan layer.
     */
    fun send(
        dst: String,
        amountSat: ULong?,
        feekbSat: ULong,
        feeSat: ULong,
        confirmations: UInt,
        selected: List<SelectedSource>,
    ) {
        val handle = wallet ?: return
        viewModelScope.launch {
            try {
                val utxos = _state.value.unspent
                val cashback = _state.value.cashbackAddr ?: _state.value.address ?: ""
                if (cashback.isEmpty()) {
                    _state.value = _state.value.copy(errorMessage = "no cashback address")
                    return@launch
                }
                val result: TxResultRecord = handle.makeTransactionMulti(
                    utxos = utxos,
                    selected = selected,
                    cashbackAddr = cashback,
                    dst = dst,
                    amountSat = amountSat,
                    feekbSat = feekbSat,
                    feeSat = feeSat,
                )
                val txid = handle.broadcast(result.txHex)
                _state.value = _state.value.copy(
                    lastTx = result,
                    lastTxid = txid,
                    errorMessage = null,
                )
            } catch (e: YubtcException) {
                _state.value = _state.value.copy(errorMessage = e.message ?: "send failed")
            }
        }
    }

    /**
     * Broadcast a hex-encoded transaction previously built by
     * [send] / [makeTransactionMulti] (or hand-crafted). Returns the
     * network txid on success.
     */
    fun broadcast(rawTxHex: String) {
        val handle = wallet ?: return
        viewModelScope.launch {
            try {
                val txid = handle.broadcast(rawTxHex)
                _state.value = _state.value.copy(lastTxid = txid, errorMessage = null)
            } catch (e: YubtcException) {
                _state.value = _state.value.copy(errorMessage = e.message ?: "broadcast failed")
            }
        }
    }

    /**
     * Switch the active network backend by name. Pass `null` (or
     * empty) to reset to the default (`blockchain.info`).
     * Settings' chip group calls this on tap. Also evicts the
     * cached scan since the on-chain view is provider-specific.
     *
     * Backend injection: the backend is local to the wallet handle
     * (there is no process-global one), so switching requires an
     * unlocked wallet and affects only this handle.
     */
    fun setBackend(name: String?) {
        viewModelScope.launch {
            val handle = wallet ?: run {
                _state.value = _state.value.copy(
                    errorMessage = "unlock a wallet before switching the backend",
                )
                return@launch
            }
            try {
                handle.setBackend(name)
                _state.value = _state.value.copy(
                    currentBackend = name?.takeIf { it.isNotEmpty() } ?: DEFAULT_BACKEND,
                    errorMessage = null,
                )
            } catch (e: YubtcException) {
                _state.value = _state.value.copy(errorMessage = e.message ?: "backend change failed")
            }
        }
    }

    /**
     * Generate a fresh BIP-39 mnemonic of `wordCount` words (one of
     * 12, 15, 18, 21, 24). The result lands in
     * [YubtcState.generatedSeed] so the Passphrase screen can show
     * it for the user to back up. The seed is **not** persisted to
     * disk — the wallet is stateless by design.
     */
    fun generateSeed(wordCount: UByte) {
        viewModelScope.launch {
            try {
                val s = uniffi.yubtc_core.generateSeed(wordCount)
                _state.value = _state.value.copy(generatedSeed = s, errorMessage = null)
            } catch (e: YubtcException) {
                _state.value = _state.value.copy(errorMessage = e.message ?: "generate failed")
            }
        }
    }

    /** Drop the generated-seed preview after the user has either
     * accepted it into the form or dismissed the flow. */
    fun dismissGeneratedSeed() {
        _state.value = _state.value.copy(generatedSeed = null)
    }

    /**
     * Clear the last built transaction (and its txid). Called by
     * the Confirm screen's "Back" action so the Send → Confirm
     * LaunchedEffect doesn't re-fire on the next composition.
     */
    fun clearLastTx() {
        _state.value = _state.value.copy(lastTx = null, lastTxid = null)
    }

    // --- Multi-sig (Phase 15) -------------------------------------------

    /**
     * Derive the multi-sig quorum address (route `ms_create`): the
     * result lands in [YubtcState.msAddress] as an
     * `MsAddressRecord` (address + redeem script hex). `n` and `m`
     * are required (R-MS-1 — the screen's fields start empty and the
     * button is disabled until both parse); `keys` are the cosigner
     * hex pubkeys; `nonce != null` derives our own legacy-form key
     * at that nonce and appends it to the quorum (`null` = watch-only
     * create). Offline pure function — no network, and with
     * `nonce == null` no seed is touched either.
     */
    fun msCreateAddress(
        n: UInt,
        m: UInt,
        keys: List<String>,
        nonce: UInt?,
        form: MsFormName,
    ) {
        val handle = wallet ?: run {
            _state.value = _state.value.copy(errorMessage = "wallet locked")
            return
        }
        viewModelScope.launch {
            try {
                val record: MsAddressRecord = handle.msCreateAddress(n, m, keys, nonce, form)
                _state.value = _state.value.copy(msAddress = record, errorMessage = null)
            } catch (e: YubtcException) {
                _state.value =
                    _state.value.copy(errorMessage = e.message ?: "ms create failed")
            }
        }
    }

    /**
     * Fetch the UTXOs of the quorum address (ОВ-13: a direct
     * `get_utxos` — the nonce walk never sees the quorum, so
     * [allUnspent] cannot serve this screen). Resolves the quorum
     * address offline via `ms_create_address`, refreshes
     * [YubtcState.msUnspent] and prunes [YubtcState.msSelectedUtxos]
     * to the fresh set (stale picks must not reach
     * `ms_build_psbt`).
     */
    fun msFetchUnspent(
        n: UInt,
        m: UInt,
        keys: List<String>,
        nonce: UInt?,
        form: MsFormName,
        confirmations: UInt,
    ) {
        val handle = wallet ?: run {
            _state.value = _state.value.copy(errorMessage = "wallet locked")
            return
        }
        viewModelScope.launch {
            try {
                val record = handle.msCreateAddress(n, m, keys, nonce, form)
                val utxos = handle.msUnspent(record.address, confirmations)
                val fresh = utxos.toSet()
                _state.value = _state.value.copy(
                    msUnspent = utxos,
                    msSelectedUtxos = _state.value.msSelectedUtxos.intersect(fresh),
                    errorMessage = null,
                )
            } catch (e: YubtcException) {
                _state.value =
                    _state.value.copy(errorMessage = e.message ?: "ms unspent fetch failed")
            }
        }
    }

    /** Toggle one quorum UTXO in the Coin Control selection
     * (mirrors [toggleUtxo] on the multi-sig set). */
    fun msToggleUtxo(utxo: UtxoWithNonce) {
        val cur = _state.value.msSelectedUtxos.toMutableSet()
        if (!cur.add(utxo)) cur.remove(utxo)
        _state.value = _state.value.copy(msSelectedUtxos = cur)
    }

    /** Select every quorum UTXO. */
    fun msSelectAllUtxos() {
        _state.value = _state.value.copy(msSelectedUtxos = _state.value.msUnspent.toSet())
    }

    /** Clear the quorum Coin Control selection. */
    fun msClearUtxoSelection() {
        _state.value = _state.value.copy(msSelectedUtxos = emptySet())
    }

    /** Convert the multi-sig selection to [SelectedSource] entries
     * for the `ms_build_psbt` boundary. */
    fun msSelectedAsSources(): List<SelectedSource> =
        _state.value.msSelectedUtxos.map {
            SelectedSource(it.nonce, it.txidHex, it.vout)
        }

    /**
     * Build + self-sign the quorum-spend PSBT (Creator + Signer in
     * one step, ОВ-12): `ms_build_psbt` over the fetched
     * [YubtcState.msUnspent] with the picked subset. Spends only
     * quorums we participate in — `nonce == null` (watch-only) is
     * refused client-side, the FFI refuses authoritatively with
     * `NotAParticipant`. On success the flow advances FORM → BUILT
     * ([MsSendFlow.afterBuild]): `state.msPsbt` holds the shareable
     * base64 PSBT, `state.msPsbtSummary` its decode preview.
     */
    fun msBuildPsbt(
        dst: String,
        amountBtc: String,
        n: UInt,
        m: UInt,
        keys: List<String>,
        nonce: UInt?,
        feekbSat: ULong,
        feeSat: ULong,
        form: MsFormName,
    ) {
        val handle = wallet ?: run {
            _state.value = _state.value.copy(errorMessage = "wallet locked")
            return
        }
        if (nonce == null) {
            _state.value = _state.value.copy(
                errorMessage = "watch-only quorum cannot spend: our key is not a participant",
            )
            return
        }
        viewModelScope.launch {
            try {
                val amountSat = uniffi.yubtc_core.btcToSatoshi(amountBtc.trim())
                val record = handle.msBuildPsbt(
                    dst = dst,
                    amountSat = amountSat,
                    n = n,
                    m = m,
                    keys = keys,
                    nonce = nonce,
                    utxos = _state.value.msUnspent,
                    selected = msSelectedAsSources(),
                    feekbSat = feekbSat,
                    feeSat = feeSat,
                    form = form,
                )
                val summary = handle.psbtDecode(record.psbtB64)
                _state.value = MsSendFlow.afterBuild(
                    _state.value,
                    psbtB64 = record.psbtB64,
                    summary = summary,
                    feeSat = record.feeSat,
                )
            } catch (e: IllegalStateException) {
                _state.value = _state.value.copy(errorMessage = e.message)
            } catch (e: YubtcException) {
                _state.value = _state.value.copy(errorMessage = e.message ?: "ms build failed")
            }
        }
    }

    /** BUILT → AWAITING: the PSBT is out with the cosigners. */
    fun msMarkAwaiting() {
        _state.value = try {
            MsSendFlow.afterAwaiting(_state.value)
        } catch (e: IllegalStateException) {
            _state.value.copy(errorMessage = e.message)
        }
    }

    /**
     * Import the combined+finalized PSBT back (paste): decode for the
     * preview and advance AWAITING → IMPORTED. A broken container
     * fails the decode — the error lands in
     * [YubtcState.errorMessage] and the state is preserved (spec:
     * отказ импорта не сбрасывает состояние; the authoritative
     * not-finalized / foreign-quorum refusals surface at the
     * extract/broadcast step).
     */
    fun msImportPsbt(psbtB64: String) {
        val handle = wallet ?: run {
            _state.value = _state.value.copy(errorMessage = "wallet locked")
            return
        }
        viewModelScope.launch {
            try {
                val summary = handle.psbtDecode(psbtB64.trim())
                _state.value = MsSendFlow.afterImport(_state.value, psbtB64.trim(), summary)
            } catch (e: IllegalStateException) {
                _state.value = _state.value.copy(errorMessage = e.message)
            } catch (e: YubtcException) {
                _state.value = _state.value.copy(errorMessage = e.message ?: "ms import failed")
            }
        }
    }

    /**
     * IMPORTED → BROADCAST: `psbt_extract` pulls the wire
     * transaction from the finalized PSBT and `broadcast` posts it;
     * the txid lands in [YubtcState.msFinalTxid] via
     * [MsSendFlow.afterBroadcast].
     */
    fun msBroadcastFinalized() {
        val handle = wallet ?: run {
            _state.value = _state.value.copy(errorMessage = "wallet locked")
            return
        }
        val imported = _state.value.msImportedPsbt ?: run {
            _state.value = _state.value.copy(errorMessage = "no finalized PSBT imported")
            return
        }
        viewModelScope.launch {
            try {
                val txHex = handle.psbtExtract(imported)
                val txid = handle.broadcast(txHex)
                _state.value = MsSendFlow.afterBroadcast(_state.value, txid)
            } catch (e: IllegalStateException) {
                _state.value = _state.value.copy(errorMessage = e.message)
            } catch (e: YubtcException) {
                _state.value = _state.value.copy(errorMessage = e.message ?: "ms broadcast failed")
            }
        }
    }

    /** Any phase → FORM («Back» / «New spend»): resets the flow
     * artifacts; the screen keeps the entered quorum. */
    fun msBackToForm() {
        _state.value = try {
            MsSendFlow.backToForm(_state.value)
        } catch (e: IllegalStateException) {
            _state.value.copy(errorMessage = e.message)
        }
    }

    /**
     * Toggle one UTXO in the Coin Control selection. The picker
     * screen calls this on each Space / tap; the Send screen reads
     * [YubtcState.selectedUtxos] to drive the "X of Y selected"
     * label and to pass the selection to
     * [makeTransactionMulti].
     */
    fun toggleUtxo(utxo: UtxoWithNonce) {
        val cur = _state.value.selectedUtxos.toMutableSet()
        if (!cur.add(utxo)) cur.remove(utxo)
        _state.value = _state.value.copy(selectedUtxos = cur)
    }

    /** Select every UTXO in the wallet (Picker's "All" key). */
    fun selectAllUtxos() {
        _state.value = _state.value.copy(
            selectedUtxos = _state.value.unspent.toSet(),
        )
    }

    /** Clear the Coin Control selection (Picker's "None" key). */
    fun clearUtxoSelection() {
        _state.value = _state.value.copy(selectedUtxos = emptySet())
    }

    /**
     * Auto-pick UTXOs via the Rust pure greedy selector.
     * [targetSat] is the send amount in satoshis (or `null` for
     * drain). The picked [SelectedSource] list is converted back to
     * [UtxoWithNonce] and stored in [YubtcState.selectedUtxos].
     * No network — runs against the cached [YubtcState.unspent].
     */
    fun autoPick(targetSat: ULong?) {
        val sources = uniffi.yubtc_core.defaultSelection(
            utxos = _state.value.unspent,
            targetSat = targetSat,
        )
        val byKey: Map<Triple<UInt, String, UInt>, UtxoWithNonce> =
            _state.value.unspent.associateBy { Triple(it.nonce, it.txidHex, it.vout) }
        val picked = sources.mapNotNull { s ->
            byKey[Triple(s.nonce, s.txidHex, s.vout)]
        }
        _state.value = _state.value.copy(selectedUtxos = picked.toSet())
    }

    /** Convert the current Coin Control selection to
     * [SelectedSource] entries for the FFI boundary. */
    fun selectedAsSources(): List<SelectedSource> =
        _state.value.selectedUtxos.map {
            SelectedSource(it.nonce, it.txidHex, it.vout)
        }

    /** Fetch the wallet's UTXOs (refreshes [YubtcState.unspent]). */
    fun refreshUtxos(confirmations: UInt = 6u) = allUnspent(confirmations)

    override fun onCleared() {
        // Final chance to release the JNA handle before the VM is
        // garbage-collected. Idempotent — `destroy()` is safe to call
        // on a handle whose native pointer was already freed.
        wallet?.destroy()
        wallet = null
    }

    private companion object {
        const val DEFAULT_BACKEND = "blockchain.info"

        /**
         * Map the persisted [SettingsRepository.addrType] value onto
         * the UniFFI enum `WalletHandle::new` expects. The repository
         * already whitelist-normalizes, so `valueOf`'s throw path is
         * unreachable through normal wiring; the fallback keeps a
         * hand-built repo from crashing the unlock.
         */
        fun addrTypeName(value: String): AddrTypeName =
            ADDR_TYPE_BY_NAME[value] ?: AddrTypeName.NATIVE

        private val ADDR_TYPE_BY_NAME: Map<String, AddrTypeName> = mapOf(
            "legacy" to AddrTypeName.LEGACY,
            "native" to AddrTypeName.NATIVE,
            "taproot" to AddrTypeName.TAPROOT,
        )
    }
}

/** High-level UI status. */
enum class WalletStatus {
    /** No seed entered yet — first screen is the passphrase / unlock form. */
    Locked,

    /** A handle is bound and screens can query address info / send. */
    Loaded,
}

/**
 * Immutable snapshot of the wallet's UI state. New values are pushed
 * through [YubtcViewModel.state] as [StateFlow] updates.
 */
data class YubtcState(
    val status: WalletStatus = WalletStatus.Locked,
    val address: String? = null,
    val addressInfo: AddressInfoRecord? = null,
    val unspent: List<UtxoWithNonce> = emptyList(),
    val cashbackAddr: String? = null,
    val selectedUtxos: Set<UtxoWithNonce> = emptySet(),
    val lastTx: TxResultRecord? = null,
    val lastTxid: String? = null,
    val currentBackend: String = "blockchain.info",
    val generatedSeed: String? = null,
    /** Auto-wipe toggle (mirrors [SettingsRepository.wipeOnIdle]). */
    val wipeOnIdle: Boolean = SharedPrefsSettingsRepository.DEFAULT_WIPE_ON_IDLE,
    /** Auto-wipe delay in minutes. Always one of 1 / 5 / 15. */
    val idleMinutes: Int = SharedPrefsSettingsRepository.DEFAULT_IDLE_MINUTES,
    /**
     * Strict BIP-39 seed reception (mirrors
     * [SettingsRepository.strictBip39]). `false` (default) is the
     * permissive mode; `true` makes the next unlock require the
     * full parse + entropy floor (R-3/R-4).
     */
    val strictBip39: Boolean = SharedPrefsSettingsRepository.DEFAULT_STRICT_BIP39,
    /**
     * Receive-address form (mirrors [SettingsRepository.addrType]):
     * `"legacy"` / `"native"` / `"taproot"`, default `"native"`.
     * Applied at the next [YubtcViewModel.unlock]; the displayed
     * [address] is the handle's receiving address in this form.
     */
    val addrType: String = SharedPrefsSettingsRepository.DEFAULT_ADDR_TYPE,
    /**
     * Pending non-blocking «Low entropy» warning (R-6), or `null`.
     * Non-null shows the warning card on the passphrase screen;
     * `Continue` re-invokes unlock with the same seed, `Edit`
     * clears this field via [YubtcViewModel.dismissLowEntropyWarning].
     */
    val lowEntropyWarning: String? = null,
    // --- Multi-sig (Phase 15) -------------------------------------------
    /**
     * Result of `ms_create_address` (route `ms_create`): the P2SH
     * quorum address + redeem script hex. `null` until the first
     * successful create.
     */
    val msAddress: MsAddressRecord? = null,
    /**
     * Phase of the multi-sig spend state machine (route `ms_send`):
     * `form → built → awaiting → imported → broadcast`. Mutated only
     * through [MsSendFlow] transitions.
     */
    val msPhase: MsSendPhase = MsSendPhase.FORM,
    /**
     * The built quorum-spend PSBT in base64 (BIP-174 transport), our
     * partial signatures included. Shareable (copy + QR).
     */
    val msPsbt: String? = null,
    /** Decode preview (`psbt_decode`) of [msPsbt]. */
    val msPsbtSummary: PsbtSummaryRecord? = null,
    /** The fee (sat) the built PSBT committed to. */
    val msBuiltFeeSat: ULong? = null,
    /** The imported combined+finalized PSBT (base64), awaiting
     * extract + broadcast. */
    val msImportedPsbt: String? = null,
    /** Decode preview (`psbt_decode`) of [msImportedPsbt]. */
    val msImportedSummary: PsbtSummaryRecord? = null,
    /** Network txid of the broadcast finalized quorum spend. */
    val msFinalTxid: String? = null,
    /**
     * UTXOs of the quorum address (ОВ-13: direct `get_utxos`; the
     * nonce walk never sees the quorum). Source set for the
     * ms_send picker; `nonce` is the `0` sentinel on every row.
     */
    val msUnspent: List<UtxoWithNonce> = emptyList(),
    /** Picked subset of [msUnspent] (Coin Control, решение #12). */
    val msSelectedUtxos: Set<UtxoWithNonce> = emptySet(),
    val errorMessage: String? = null,
)