package io.yubtc.wallet.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test
import uniffi.yubtc_core.PsbtInputSummaryRecord
import uniffi.yubtc_core.PsbtOutputSummaryRecord
import uniffi.yubtc_core.PsbtSummaryRecord
import uniffi.yubtc_core.UtxoWithNonce

/**
 * Pure-JVM tests for the multi-sig spend state machine
 * ([MsSendPhase] + [MsSendFlow], Phase 15).
 *
 * The [YubtcViewModel] only applies these transitions after the
 * corresponding UniFFI step succeeded; the FFI handle itself is
 * JNA-backed and cannot load on the JVM, so the machine is driven
 * here with fake records (the uniffi `*Record` data classes are
 * plain Kotlin data — no native calls in their constructors).
 * Every transition, every wrong-phase guard and the artifact
 * invalidation rules are pinned:
 *
 * ```
 * form → built → awaiting → imported → broadcast
 * ```
 */
class MsSendFlowTest {

    /** A fake decode summary, as `psbt_decode` would return it. */
    private fun fakeSummary(
        txid: String = "ab".repeat(32),
        partialSigs: ULong = 1uL,
        finalizedInputs: Boolean = false,
        feeSat: ULong? = 500uL,
    ) = PsbtSummaryRecord(
        txidHex = txid,
        version = 2u,
        inputs = listOf(
            PsbtInputSummaryRecord(
                hasUtxo = true,
                nPartialSigs = partialSigs,
                sighashType = null,
                finalized = finalizedInputs,
            ),
        ),
        outputs = listOf(
            PsbtOutputSummaryRecord(
                amountSat = 50_000uL,
                scriptPubkeyHex = "0014" + "cd".repeat(20),
            ),
        ),
        feeSat = feeSat,
    )

    private val psbtB64 = "cHNidP8BAFICAAAA"
    private val importedB64 = "cHNidP8BAFICAAAAZmluYWxpemVk"

    private fun builtState(): YubtcState = MsSendFlow.afterBuild(
        YubtcState(), psbtB64, fakeSummary(partialSigs = 1uL), 750uL,
    )

    private fun awaitingState(): YubtcState = MsSendFlow.afterAwaiting(builtState())

    private fun importedState(): YubtcState = MsSendFlow.afterImport(
        awaitingState(), importedB64, fakeSummary(finalizedInputs = true),
    )

    // --- happy path -------------------------------------------------------

    @Test
    fun formToBuiltStoresPsbtSummaryAndFee() {
        val state = builtState()
        assertEquals(MsSendPhase.BUILT, state.msPhase)
        assertEquals(psbtB64, state.msPsbt)
        assertEquals(1uL, state.msPsbtSummary?.inputs?.first()?.nPartialSigs)
        assertEquals(750uL, state.msBuiltFeeSat)
        assertNull(state.msFinalTxid)
    }

    @Test
    fun builtToAwaitingKeepsThePsbtArtifacts() {
        val state = awaitingState()
        assertEquals(MsSendPhase.AWAITING, state.msPhase)
        assertEquals(psbtB64, state.msPsbt)
    }

    @Test
    fun awaitingToImportedStoresTheFinalizedContainer() {
        val state = importedState()
        assertEquals(MsSendPhase.IMPORTED, state.msPhase)
        assertEquals(importedB64, state.msImportedPsbt)
        assertEquals(true, state.msImportedSummary?.inputs?.first()?.finalized)
        // The built PSBT stays visible for reference.
        assertEquals(psbtB64, state.msPsbt)
    }

    @Test
    fun importedToBroadcastStoresTheTxid() {
        val state = MsSendFlow.afterBroadcast(importedState(), "deadbeef")
        assertEquals(MsSendPhase.BROADCAST, state.msPhase)
        assertEquals("deadbeef", state.msFinalTxid)
    }

    // --- rebuild invalidates the import chain -----------------------------

    @Test
    fun rebuildFromAwaitingReplacesArtifactsAndDropsStaleImport() {
        val rebuilt = MsSendFlow.afterBuild(
            awaitingState(), "cHNidP8BAHJlYnVpbGQ=", fakeSummary(txid = "ff".repeat(32)), 900uL,
        )
        assertEquals(MsSendPhase.BUILT, rebuilt.msPhase)
        assertEquals("cHNidP8BAHJlYnVpbGQ=", rebuilt.msPsbt)
        assertNull(rebuilt.msImportedPsbt)
        assertNull(rebuilt.msImportedSummary)
        assertNull(rebuilt.msFinalTxid)
    }

    // --- wrong-phase guards -----------------------------------------------

    @Test
    fun awaitingFromFormIsRejected() {
        try {
            MsSendFlow.afterAwaiting(YubtcState())
            fail("awaiting must only be reachable from BUILT")
        } catch (_: IllegalStateException) {
        }
    }

    @Test
    fun importFromBuiltIsRejected() {
        try {
            MsSendFlow.afterImport(builtState(), importedB64, fakeSummary())
            fail("import must only be reachable from AWAITING/IMPORTED")
        } catch (_: IllegalStateException) {
        }
    }

    @Test
    fun importFromFormIsRejected() {
        try {
            MsSendFlow.afterImport(YubtcState(), importedB64, fakeSummary())
            fail("import must only be reachable from AWAITING/IMPORTED")
        } catch (_: IllegalStateException) {
        }
    }

    @Test
    fun broadcastFromAwaitingIsRejected() {
        try {
            MsSendFlow.afterBroadcast(awaitingState(), "deadbeef")
            fail("broadcast must only be reachable from IMPORTED")
        } catch (_: IllegalStateException) {
        }
    }

    @Test
    fun broadcastFromFormIsRejected() {
        try {
            MsSendFlow.afterBroadcast(YubtcState(), "deadbeef")
            fail("broadcast must only be reachable from IMPORTED")
        } catch (_: IllegalStateException) {
        }
    }

    // --- back to form -------------------------------------------------------

    @Test
    fun backToFormFromFormIsRejected() {
        try {
            MsSendFlow.backToForm(YubtcState())
            fail("there is nothing to go back to from FORM")
        } catch (_: IllegalStateException) {
        }
    }

    @Test
    fun backToFormClearsTheFlowArtifactsButKeepsTheWalletState() {
        val back = MsSendFlow.backToForm(importedState())
        assertEquals(MsSendPhase.FORM, back.msPhase)
        assertNull(back.msPsbt)
        assertNull(back.msPsbtSummary)
        assertNull(back.msBuiltFeeSat)
        assertNull(back.msImportedPsbt)
        assertNull(back.msImportedSummary)
        assertNull(back.msFinalTxid)
        // Unrelated state is untouched (quorum inputs live on the
        // screen and are not part of the flow).
        assertEquals(WalletStatus.Locked, back.status)
        assertEquals(emptyList<UtxoWithNonce>(), back.msUnspent)
    }

    @Test
    fun backToFormWorksFromBroadcastForANewSpend() {
        val broadcast = MsSendFlow.afterBroadcast(importedState(), "deadbeef")
        val back = MsSendFlow.backToForm(broadcast)
        assertEquals(MsSendPhase.FORM, back.msPhase)
        assertNull(back.msFinalTxid)
    }

    // --- error path: state preserved ----------------------------------------

    @Test
    fun failedTransitionLeavesTheStateUnchanged() {
        val state = builtState()
        try {
            MsSendFlow.afterBroadcast(state, "deadbeef")
            fail("guarded")
        } catch (_: IllegalStateException) {
        }
        // The machine is pure: the rejected transition cannot have
        // mutated the previous state (VM surfaces the error instead).
        assertEquals(MsSendPhase.BUILT, state.msPhase)
        assertEquals(psbtB64, state.msPsbt)
    }
}
