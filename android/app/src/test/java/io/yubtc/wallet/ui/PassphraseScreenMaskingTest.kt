package io.yubtc.wallet.ui

import io.yubtc.wallet.ui.screens.seedFieldMasked
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the PassphraseScreen seed-masking rule
 * ([seedFieldMasked]).
 *
 * The rule mirrors the CLI prompt contract (commit c4233d3): the
 * seed input is hidden while the entered passphrase is empty, and
 * shown in plain text once a passphrase exists. The passphrase is
 * compared raw — it is never trimmed, because BIP-39 passphrases
 * may contain leading / trailing spaces.
 */
class PassphraseScreenMaskingTest {

    @Test
    fun emptyPassphraseMasksSeed() {
        // No passphrase — the seed is the only secret on screen,
        // so it is masked (like the CLI's hidden seed read).
        assertTrue(seedFieldMasked(""))
    }

    @Test
    fun nonEmptyPassphraseShowsSeedInPlainText() {
        assertFalse(seedFieldMasked("orange"))
    }

    @Test
    fun passphraseIsComparedRawNotTrimmed() {
        // A whitespace-only passphrase is non-empty (BIP-39 allows
        // leading / trailing spaces and the field never trims), so
        // the seed stays plain text.
        assertFalse(seedFieldMasked(" "))
    }
}
