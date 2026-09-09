package io.yubtc.wallet.data

/**
 * BIP-21 payment URI.
 *
 * Spec: <https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki>.
 *
 * Format
 * ------
 *
 * ```
 * bitcoin:<address>[?amount=<btc>][&label=<urlencoded>][&message=<urlencoded>]
 * ```
 *
 * - `<address>` is mandatory. For v1 we accept only P2PKH and
 *   P2SH outputs (the wallet rejects P2WPKH / P2WSH anyway — see
 *   `core/src/wallet.rs:make_lock_script_for_address`). The BIP-21
 *   spec also allows `bitcoin-URI` parameters; we treat only the
 *   three documented core parameters as first-class.
 * - `<btc>` is a **decimal** value, never satoshis. The BIP-21
 *   grammar says amounts below `0.00000546` are
 *   "considered invalid" — but `Bip21Uri` itself does not enforce
 *   that; the lower bound is a 1-satoshi constraint against the
 *   network's chosen precision. The Receive screen rounds inputs
 *   to the wallet's `satoshiToBtc` formatter before encoding.
 * - `label` and `message` are URL-encoded (`%xx` form for any
 *   byte outside `[A-Za-z0-9-._~]`). The encoder uses a tight
 *   allow-list rather than blanket URI encoding so `:` and `@`
 *   characters in particular do not get mis-routed by a
 *   scanner-side URL parser.
 *
 * Locale: `Bip21Uri` is data only — the URI string is what ends up
 * in the QR. Decimal separator is forced to `.` regardless of the
 * device locale; BIP-21 spec section "Amount" requires the dot
 * form.
 */
data class Bip21Uri(
    val address: String,
    val amountBtc: String? = null,
    val label: String? = null,
    val message: String? = null,
) {
    init {
        require(address.isNotBlank()) { "BIP-21 requires a non-empty address" }
        amountBtc?.takeIf { it.isNotEmpty() }?.let {
            require(it.matches(AMOUNT_PATTERN)) {
                "amountBtc must be a non-negative decimal with at most 8 " +
                    "fractional digits: $it"
            }
        }
    }

    /**
     * Render to the canonical BIP-21 string. Always starts with
     * `bitcoin:`. Subsequent parameters only render when the
     * backing field is non-null and non-empty — calling
     * `toUriString()` on an `amountBtc == null` produces
     * `bitcoin:<address>` exactly (no trailing `?`).
     *
     * Never throws: [amountBtc] was validated at construction time
     * against [AMOUNT_PATTERN], so by the time this runs every field
     * is renderable. The caller (Receive screen) gates input with the
     * same pattern before constructing the URI, so an invalid amount
     * never reaches the constructor either.
     */
    fun toUriString(): String {
        val sb = StringBuilder("bitcoin:")
        sb.append(address)
        val params = mutableListOf<Pair<String, String>>()
        amountBtc?.takeIf { it.isNotEmpty() }?.let { params += "amount" to it }
        label?.takeIf { it.isNotEmpty() }?.let { params += "label" to encodeQueryValue(it) }
        message?.takeIf { it.isNotEmpty() }?.let { params += "message" to encodeQueryValue(it) }
        if (params.isNotEmpty()) {
            sb.append('?')
            sb.append(params.joinToString("&") { (k, v) -> "$k=$v" })
        }
        return sb.toString()
    }

    companion object {
        /**
         * Regex the wallet treats as a valid amount string: a
         * non-negative decimal, optional leading zeros (e.g. `0.5`,
         * `00.5`, `0`), never a sign (BIP-21 disallows amounts
         * like `-0.1`). The trailing fractional part is limited
         * to 8 digits — anything finer than a satoshi is
         * unrepresentable.
         */
        val AMOUNT_PATTERN = Regex("^(0|[1-9][0-9]*)(?:\\.[0-9]{1,8})?$")

        /**
         * Encode a single query value per RFC 3986 "unreserved"
         * characters. The allow-list `[A-Za-z0-9-._~]` matches the
         * spec exactly; every other byte — including space,
         * percent, plus, equal — is rendered as `%xx`.
         */
        internal fun encodeQueryValue(v: String): String {
            val sb = StringBuilder(v.length)
            for (byte in v.toByteArray(Charsets.UTF_8)) {
                val c = byte.toInt() and 0xff
                when {
                    c in 0x30..0x39 || c in 0x41..0x5a || c in 0x61..0x7a -> sb.append(c.toChar())
                    c == 0x2d || c == 0x2e || c == 0x5f || c == 0x7e -> sb.append(c.toChar())
                    else -> sb.append('%')
                        .append(HEX[(c shr 4) and 0xf])
                        .append(HEX[c and 0xf])
                }
            }
            return sb.toString()
        }

        private val HEX = "0123456789ABCDEF".toCharArray()
    }
}
