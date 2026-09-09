package io.yubtc.wallet.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.yubtc_core.MsFormName

/**
 * Pure-JVM tests for [MsQuorum] — the client-side multi-sig
 * validation mirror (Phase 15, R-MS-1/2/3).
 *
 * The critical contract is **R-MS-1 (no defaults)**: an empty or
 * unparseable N/M field yields `null` — never a substituted value —
 * so a quorum can never be created from half-typed input. The
 * bounds check (R-MS-2) and the key format check (R-MS-3) mirror
 * the authoritative `MsError` refusals of the core; the FFI
 * re-validates everything.
 */
class MsQuorumTest {

    // --- parseCount: R-MS-1 (no defaults) --------------------------------

    @Test
    fun blankCountParsesToNull_notToADefault() {
        assertNull(MsQuorum.parseCount(""))
        assertNull(MsQuorum.parseCount("   "))
    }

    @Test
    fun nonNumericCountParsesToNull() {
        assertNull(MsQuorum.parseCount("abc"))
        assertNull(MsQuorum.parseCount("2x3"))
        assertNull(MsQuorum.parseCount("2.5"))
        assertNull(MsQuorum.parseCount("2,5"))
    }

    @Test
    fun negativeCountParsesToNull() {
        assertNull(MsQuorum.parseCount("-1"))
    }

    @Test
    fun validCountsParseWithSurroundingWhitespace() {
        assertEquals(3, MsQuorum.parseCount("3"))
        assertEquals(4, MsQuorum.parseCount(" 4 "))
        assertEquals(0, MsQuorum.parseCount("0"))
        assertEquals(15, MsQuorum.parseCount("15"))
    }

    // --- quorumError: R-MS-2 (bounds), R-MS-1 (required fields) ----------

    @Test
    fun missingNReportsRequired_noDefaultValueIsAssumed() {
        assertEquals(MsQuorum.MSG_N_REQUIRED, MsQuorum.quorumError(null, 2))
        assertEquals(MsQuorum.MSG_N_REQUIRED, MsQuorum.quorumError(null, null))
    }

    @Test
    fun missingMReportsRequired_noDefaultValueIsAssumed() {
        assertEquals(MsQuorum.MSG_M_REQUIRED, MsQuorum.quorumError(3, null))
    }

    @Test
    fun zeroThresholdIsOutOfBounds() {
        assertEquals(MsQuorum.MSG_QUORUM_BOUNDS, MsQuorum.quorumError(2, 0))
    }

    @Test
    fun thresholdAboveTotalIsOutOfBounds() {
        assertEquals(MsQuorum.MSG_QUORUM_BOUNDS, MsQuorum.quorumError(2, 3))
    }

    @Test
    fun totalAboveFifteenIsOutOfBounds() {
        assertEquals(MsQuorum.MSG_QUORUM_BOUNDS, MsQuorum.quorumError(16, 16))
        assertEquals(MsQuorum.MSG_QUORUM_BOUNDS, MsQuorum.quorumError(20, 2))
    }

    @Test
    fun boundaryTuplesAreAccepted() {
        assertNull(MsQuorum.quorumError(1, 1))
        assertNull(MsQuorum.quorumError(3, 2))
        assertNull(MsQuorum.quorumError(15, 15))
        assertNull(MsQuorum.quorumError(15, 1))
    }

    // --- keyError: R-MS-3/R-MS-10 (form-dependent key encodings) -----

    @Test
    fun emptyKeyReportsEmpty_notLength() {
        assertEquals(MsQuorum.MSG_KEY_EMPTY, MsQuorum.keyError("", MsFormName.P2SH))
        assertEquals(MsQuorum.MSG_KEY_EMPTY, MsQuorum.keyError("   ", MsFormName.P2WSH))
        assertEquals(MsQuorum.MSG_KEY_EMPTY, MsQuorum.keyError("", MsFormName.P2TR))
    }

    @Test
    fun wrongLengthKeysAreRejected() {
        val body = "a".repeat(64)
        assertEquals(MsQuorum.MSG_KEY_LENGTH, MsQuorum.keyError("02$body" + "0", MsFormName.P2SH))
        assertEquals(
            MsQuorum.MSG_KEY_LENGTH,
            MsQuorum.keyError("02${body.dropLast(1)}", MsFormName.P2SH),
        )
    }

    @Test
    fun uncompressedPrefixIsRejected() {
        assertEquals(MsQuorum.MSG_KEY_PREFIX, MsQuorum.keyError("04" + "ab".repeat(32), MsFormName.P2SH))
        assertEquals(MsQuorum.MSG_KEY_PREFIX, MsQuorum.keyError("01" + "ab".repeat(32), MsFormName.P2WSH))
    }

    @Test
    fun nonHexCharactersAreRejected() {
        assertEquals(MsQuorum.MSG_KEY_HEX, MsQuorum.keyError("02" + "gg".repeat(32), MsFormName.P2SH))
        // WIF-shaped input is not a pubkey.
        assertEquals(
            MsQuorum.MSG_KEY_LENGTH,
            MsQuorum.keyError("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", MsFormName.P2SH),
        )
    }

    @Test
    fun validCompressedKeysAreAccepted_inBothPrefixesAndCases() {
        assertNull(MsQuorum.keyError("02" + "ab".repeat(32), MsFormName.P2SH))
        assertNull(MsQuorum.keyError("03" + "AB".repeat(32), MsFormName.P2WSH))
        assertNull(MsQuorum.keyError(" 03" + "ab".repeat(32) + " ", MsFormName.P2SH))
    }

    // --- keyError, p2tr: R-MS-10 (x-only 64-hex grammar) --------------

    @Test
    fun p2trAcceptsXOnlyHexKeys_inBothCasesAndWhitespace() {
        assertNull(MsQuorum.keyError("ab".repeat(32), MsFormName.P2TR))
        assertNull(MsQuorum.keyError("AB".repeat(32), MsFormName.P2TR))
        assertNull(MsQuorum.keyError(" " + "ab".repeat(32) + " ", MsFormName.P2TR))
    }

    @Test
    fun p2trRejectsACompressedKeyAsTheWrongLength() {
        // The 66-char compressed encoding is not the p2tr grammar —
        // the same input that passes for p2sh fails for p2tr
        // (mirror of core `parse_ms_keys`, R-MS-10).
        val compressed = "02" + "ab".repeat(32)
        assertEquals(MsQuorum.MSG_KEY_LENGTH_XONLY, MsQuorum.keyError(compressed, MsFormName.P2TR))
    }

    @Test
    fun p2trRejectsOddLengthAndNonHexXOnlyValues() {
        assertEquals(
            MsQuorum.MSG_KEY_LENGTH_XONLY,
            MsQuorum.keyError("ab".repeat(31) + "a", MsFormName.P2TR),
        )
        assertEquals(MsQuorum.MSG_KEY_HEX, MsQuorum.keyError("gg".repeat(32), MsFormName.P2TR))
        // WIF-shaped input is not an x-only pubkey either.
        assertEquals(
            MsQuorum.MSG_KEY_LENGTH_XONLY,
            MsQuorum.keyError("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", MsFormName.P2TR),
        )
    }

    // --- duplicateIndexes: R-MS-3 (duplicate keys) ------------------------

    @Test
    fun duplicatesAreFlaggedOnEveryLaterOccurrence() {
        val keys = listOf("02" + "ab".repeat(32), "03" + "cd".repeat(32), "02" + "ab".repeat(32))
        assertEquals(setOf(2), MsQuorum.duplicateIndexes(keys))
    }

    @Test
    fun duplicateDetectionIsCaseInsensitive() {
        val keys = listOf("02" + "ab".repeat(32), "02" + "AB".repeat(32))
        assertEquals(setOf(1), MsQuorum.duplicateIndexes(keys))
    }

    @Test
    fun blankKeysAreNeverFlaggedAsDuplicates() {
        val keys = listOf("", "   ", "02" + "ab".repeat(32))
        assertEquals(emptySet<Int>(), MsQuorum.duplicateIndexes(keys))
    }

    // --- requiredKeyCount -------------------------------------------------

    @Test
    fun watchOnlyNeedsAllNKeys() {
        assertEquals(3, MsQuorum.requiredKeyCount(3, ownKeyInQuorum = false))
        assertEquals(1, MsQuorum.requiredKeyCount(1, ownKeyInQuorum = false))
    }

    @Test
    fun ownKeyJoinsTheQuorumSoOneFewerCosignerRowIsNeeded() {
        assertEquals(2, MsQuorum.requiredKeyCount(3, ownKeyInQuorum = true))
        assertEquals(0, MsQuorum.requiredKeyCount(1, ownKeyInQuorum = true))
    }

    // --- quorum form (v0.3) -----------------------------------------------

    @Test
    fun formNamesMatchTheCliFlagSpelling() {
        // The canonical `--form` values; the selector's labels and the
        // FFI round trip both use these spellings.
        assertEquals("p2sh", MsQuorum.formName(MsFormName.P2SH))
        assertEquals("p2wsh", MsQuorum.formName(MsFormName.P2WSH))
        assertEquals("p2tr", MsQuorum.formName(MsFormName.P2TR))
    }

    @Test
    fun formHintsDescribeTheAddressEncodingNotTheQuorum() {
        // The hint must promise only the address/spend-form change
        // (for p2tr additionally the script form and the key
        // encoding — the quorum tuple semantics stay the same).
        assertTrue(MsQuorum.formHint(MsFormName.P2SH).contains("3…"))
        assertTrue(MsQuorum.formHint(MsFormName.P2WSH).contains("bc1q…"))
        assertTrue(MsQuorum.formHint(MsFormName.P2TR).contains("bc1p…"))
        assertTrue(MsQuorum.formHint(MsFormName.P2TR).contains("x-only"))
        assertFalse(MsQuorum.formHint(MsFormName.P2SH) == MsQuorum.formHint(MsFormName.P2WSH))
        assertFalse(MsQuorum.formHint(MsFormName.P2WSH) == MsQuorum.formHint(MsFormName.P2TR))
    }

    @Test
    fun keyFieldLabelsFollowTheFormEncoding() {
        // R-MS-10: the row label names the encoding the selected
        // form expects.
        assertEquals("compressed hex pubkey", MsQuorum.keyFieldLabel(MsFormName.P2SH))
        assertEquals("compressed hex pubkey", MsQuorum.keyFieldLabel(MsFormName.P2WSH))
        assertEquals("x-only hex pubkey", MsQuorum.keyFieldLabel(MsFormName.P2TR))
    }

    @Test
    fun p2trClientGateAcceptsAWellFormedXOnlyQuorum() {
        // The full client-side gate for a p2tr tuple: bounds OK and
        // every row passes the x-only grammar.
        assertNull(MsQuorum.quorumError(3, 2))
        val keys = listOf("ab".repeat(32), "cd".repeat(32))
        assertTrue(keys.all { MsQuorum.keyError(it, MsFormName.P2TR) == null })
        assertEquals(emptySet<Int>(), MsQuorum.duplicateIndexes(keys))
    }

    // --- constants --------------------------------------------------------

    @Test
    fun maxPubkeysMatchesTheCoreBound() {
        // R-MS-2: 15, not the consensus 20-key cap (520-byte push limit).
        assertEquals(15, MsQuorum.MAX_PUBKEYS)
    }

    @Test
    fun keyHexLengthMatchesCompressedPubkeys() {
        assertEquals(66, MsQuorum.KEY_HEX_LENGTH)
    }

    @Test
    fun keyHexLengthXonlyMatchesBip340Pubkeys() {
        // R-MS-10: 32 bytes as 64 hex chars, no prefix.
        assertEquals(64, MsQuorum.KEY_HEX_LENGTH_XONLY)
    }
}
