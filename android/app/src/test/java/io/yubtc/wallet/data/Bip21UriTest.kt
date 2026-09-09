package io.yubtc.wallet.data

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pure-JVM tests for [Bip21Uri].
 *
 * The BIP-21 grammar allows the canonical `bitcoin:` scheme and
 * exactly three parameters (`amount`, `label`, `message`); this
 * suite pins every combination we exercise from the wallet UI,
 * plus a few edge cases (UTF-8, percent-encoding, amount with
 * no leading zero).
 */
class Bip21UriTest {

    @Test
    fun addressOnlyYieldsBareUri() {
        val uri = Bip21Uri(address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT")
        assertEquals(
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            uri.toUriString(),
        )
    }

    @Test
    fun amountOnlyAppendsAmountParam() {
        val uri = Bip21Uri(
            address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            amountBtc = "0.1",
        )
        assertEquals(
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.1",
            uri.toUriString(),
        )
    }

    @Test
    fun labelAndMessageAppendInCanonicalOrder() {
        val uri = Bip21Uri(
            address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            amountBtc = "0.5",
            label = "Donation",
            message = "Thanks for the help",
        )
        assertEquals(
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT" +
                "?amount=0.5&label=Donation&message=Thanks%20for%20the%20help",
            uri.toUriString(),
        )
    }

    @Test
    fun nullFieldsAreNotRendered() {
        val uri = Bip21Uri(
            address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            amountBtc = "0.5",
            label = null,
            message = null,
        )
        // No trailing `?`, only the parameter that was set.
        assertEquals(
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.5",
            uri.toUriString(),
        )
    }

    @Test
    fun emptyFieldsAreTreatedAsNull() {
        val uri = Bip21Uri(
            address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            amountBtc = "0",
            label = "",
            message = "",
        )
        assertEquals(
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0",
            uri.toUriString(),
        )
    }

    @Test
    fun amountZeroIsAllowed() {
        // BIP-21 permits amount=0 — it is the "address only" form
        // for senders who want to round-trip the URI scanner.
        val uri = Bip21Uri(address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT", amountBtc = "0")
        assertEquals(
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0",
            uri.toUriString(),
        )
    }

    @Test
    fun utf8LabelIsPercentEncoded() {
        val uri = Bip21Uri(
            address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            label = "привет",
        )
        // "привет" UTF-8 bytes: D0 BF D1 80 D0 B8 D0 B2 D0 B5 D1 82
        assertEquals(
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT" +
                "?label=%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82",
            uri.toUriString(),
        )
    }

    @Test
    fun specialCharactersInLabelArePercentEncoded() {
        val uri = Bip21Uri(
            address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            label = "a=b&c",
        )
        // `=` and `&` MUST be percent-encoded so a wallet that
        // splits on `&` to read multi-parameter URIs does not
        // mis-parse them.
        assertEquals(
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT" +
                "?label=a%3Db%26c",
            uri.toUriString(),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun blankAddressIsRejected() {
        Bip21Uri(address = "")
    }

    @Test(expected = IllegalArgumentException::class)
    fun invalidAmountStringIsRejected() {
        Bip21Uri(address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT", amountBtc = "-0.5")
    }

    @Test(expected = IllegalArgumentException::class)
    fun tooManyFractionalDigitsRejected() {
        Bip21Uri(
            address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            amountBtc = "0.123456789",
        )
    }
}
