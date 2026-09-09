package io.yubtc.wallet.data

import uniffi.yubtc_core.PsbtSummaryRecord

/**
 * Phase of the multi-sig spend state machine (spec.md «Принято
 * (2026-09-02): полный surface», MsSendScreen contract):
 *
 * ```
 * form → built → awaiting (out-of-band rounds) → imported → broadcast
 * ```
 *
 * - [FORM] — quorum + destination + amount + fee + input picking.
 * - [BUILT] — `ms_build_psbt` produced the PSBT (own key already
 *   signed); displayed / shareable (copy + QR).
 * - [AWAITING] — the PSBT is out with the cosigners; the screen
 *   accepts the combined+finalized PSBT back.
 * - [IMPORTED] — the finalized PSBT decodes; preview shown, ready to
 *   broadcast.
 * - [BROADCAST] — extracted + broadcast; `msFinalTxid` holds the
 *   network txid. Terminal phase; «New spend» returns to [FORM].
 *
 * Data-driven per the UI.md conventions: transitions happen only
 * through [YubtcViewModel] mutations, and an FFI refusal never
 * advances the phase — the error lands in
 * [YubtcState.errorMessage] with the state preserved.
 */
enum class MsSendPhase {
    FORM,
    BUILT,
    AWAITING,
    IMPORTED,
    BROADCAST,
}

/**
 * Pure state-machine transitions for the multi-sig spend flow.
 *
 * Each function takes the current [YubtcState] and returns the next
 * one; a transition fired from the wrong phase throws
 * [IllegalStateException] — the ViewModel only calls them after the
 * corresponding FFI step succeeded, so a thrown guard is a wiring
 * bug, not a user-facing path. Kept free of UniFFI *calls* (records
 * are plain data) so the JVM unit suite can drive every transition
 * with fake records.
 *
 * The user's quorum inputs (N, M, key list, own-key toggle, nonce)
 * are screen-local Compose state and survive every transition here —
 * «назад на любом шаге — без потери введённых N/M/ключей до
 * успешного broadcast» (spec). [backToForm] only resets the flow
 * artifacts (PSBT, summaries, txid).
 */
object MsSendFlow {

    /**
     * FORM → BUILT: the build succeeded. Stores the base64 PSBT
     * ([YubtcState.msPsbt]), its decoded summary and the committed
     * fee; a rebuild from BUILT/AWAITING replaces the artifacts and
     * discards any stale import chain (a new build invalidates the
     * previously circulated PSBT).
     */
    fun afterBuild(
        state: YubtcState,
        psbtB64: String,
        summary: PsbtSummaryRecord,
        feeSat: ULong,
    ): YubtcState {
        checkPhase(state, setOf(MsSendPhase.FORM, MsSendPhase.BUILT, MsSendPhase.AWAITING), "build")
        return state.copy(
            msPhase = MsSendPhase.BUILT,
            msPsbt = psbtB64,
            msPsbtSummary = summary,
            msBuiltFeeSat = feeSat,
            msImportedPsbt = null,
            msImportedSummary = null,
            msFinalTxid = null,
            errorMessage = null,
        )
    }

    /**
     * BUILT → AWAITING: the user handed the PSBT to the cosigners
     * (out-of-band signing rounds).
     */
    fun afterAwaiting(state: YubtcState): YubtcState {
        checkPhase(state, setOf(MsSendPhase.BUILT), "awaiting")
        return state.copy(msPhase = MsSendPhase.AWAITING, errorMessage = null)
    }

    /**
     * AWAITING → IMPORTED: the combined+finalized PSBT came back and
     * decodes (preview). Re-import from IMPORTED is allowed (another
     * finalized container).
     */
    fun afterImport(
        state: YubtcState,
        psbtB64: String,
        summary: PsbtSummaryRecord,
    ): YubtcState {
        checkPhase(state, setOf(MsSendPhase.AWAITING, MsSendPhase.IMPORTED), "import")
        return state.copy(
            msPhase = MsSendPhase.IMPORTED,
            msImportedPsbt = psbtB64,
            msImportedSummary = summary,
            errorMessage = null,
        )
    }

    /**
     * IMPORTED → BROADCAST: extract + broadcast succeeded;
     * [YubtcState.msFinalTxid] holds the network txid. Terminal.
     */
    fun afterBroadcast(state: YubtcState, txid: String): YubtcState {
        checkPhase(state, setOf(MsSendPhase.IMPORTED), "broadcast")
        return state.copy(msPhase = MsSendPhase.BROADCAST, msFinalTxid = txid, errorMessage = null)
    }

    /**
     * Any non-FORM phase → FORM: resets the flow artifacts. The
     * quorum inputs live on the screen and are untouched; from
     * BROADCAST this is the «New spend» action.
     */
    fun backToForm(state: YubtcState): YubtcState {
        if (state.msPhase == MsSendPhase.FORM) {
            throw IllegalStateException("already in FORM")
        }
        return state.copy(
            msPhase = MsSendPhase.FORM,
            msPsbt = null,
            msPsbtSummary = null,
            msBuiltFeeSat = null,
            msImportedPsbt = null,
            msImportedSummary = null,
            msFinalTxid = null,
        )
    }

    private fun checkPhase(state: YubtcState, allowed: Set<MsSendPhase>, action: String) {
        if (state.msPhase !in allowed) {
            throw IllegalStateException(
                "ms send: $action is not allowed from phase ${state.msPhase} " +
                    "(allowed: $allowed)",
            )
        }
    }
}
