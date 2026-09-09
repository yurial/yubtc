package io.yubtc.wallet.data

import uniffi.yubtc_core.MsFormName

/**
 * Client-side multi-sig quorum validation (Phase 15, R-MS-1/2/3;
 * v0.3 adds the form selector helpers and the R-MS-10 key-encoding
 * split).
 *
 * Pure Kotlin — no UniFFI / native calls (the [MsFormName] import is
 * the generated plain enum, no `.so` involvement) — so the screens
 * can gate their buttons and highlight bad rows offline, and the JVM
 * unit suite can pin the contract directly. The *authoritative*
 * refusals come from the core (`MsError::QuorumBounds` /
 * `DuplicateKey` / `KeyCountMismatch` / `InvalidKeyEncoding` through
 * the FFI); this mirror only repeats the client-checkable subset so
 * the user sees field-level errors before a round-trip. Spec rules:
 *
 * - **R-MS-1** — N and M have no defaults: an empty field is never
 *   interpreted as a number, the build button stays unavailable
 *   until both are entered.
 * - **R-MS-2** — `1 ≤ M ≤ N ≤ 15` (the 15 bound is the 520-byte
 *   push limit, not the consensus 20-key cap; v0.3 keeps it as the
 *   cross-form bound for all three quorum forms — R-MS-9: the
 *   15-key tapscript leaf is 512 bytes, under the same limit).
 * - **R-MS-3/R-MS-10** — the key encoding is form-dependent:
 *   compressed hex pubkeys (`02…`/`03…`, 66 hex chars) for
 *   p2sh/p2wsh, x-only hex pubkeys (64 hex chars) for p2tr —
 *   mirroring the core `parse_ms_keys`; duplicates highlighted and
 *   blocked.
 */
object MsQuorum {

    /** Upper bound of the quorum (mirror of core `fwd::MS_MAX_PUBKEYS`). */
    const val MAX_PUBKEYS: Int = 15

    /** Compressed secp256k1 pubkey in hex: `02`/`03` prefix + 64 hex digits. */
    const val KEY_HEX_LENGTH: Int = 66

    /** x-only (BIP-340) pubkey in hex: 32 bytes as 64 hex digits (R-MS-10, p2tr). */
    const val KEY_HEX_LENGTH_XONLY: Int = 64

    private val KEY_PATTERN = Regex("^(02|03)[0-9a-fA-F]{${KEY_HEX_LENGTH - 2}}$")

    private val XONLY_KEY_PATTERN = Regex("^[0-9a-fA-F]{${KEY_HEX_LENGTH_XONLY}}$")

    /**
     * Parse a count field (N or M). Returns `null` when the field is
     * blank or not a pure decimal — `null` means "not entered yet",
     * never a default (R-MS-1). Callers must treat `null` as "keep
     * the button disabled", not "substitute a value".
     */
    fun parseCount(text: String): Int? {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return null
        return trimmed.toIntOrNull()?.takeIf { it >= 0 }
    }

    /**
     * The quorum-bounds client check (R-MS-2, the local
     * `QuorumBounds` equivalent). `n` / `m` are the parsed counts —
     * `null` (not entered, R-MS-1) yields the required-field message
     * for the missing field. Returns `null` when the tuple is
     * client-valid; the FFI re-validates authoritatively.
     */
    fun quorumError(n: Int?, m: Int?): String? {
        if (n == null) return MSG_N_REQUIRED
        if (m == null) return MSG_M_REQUIRED
        if (m < 1) return MSG_QUORUM_BOUNDS
        if (m > n) return MSG_QUORUM_BOUNDS
        if (n > MAX_PUBKEYS) return MSG_QUORUM_BOUNDS
        return null
    }

    /**
     * Per-key format check (R-MS-3/R-MS-10) against the selected
     * form's encoding. Returns `null` for a valid key — compressed
     * hex (66 chars, `02`/`03` prefix) for p2sh/p2wsh, x-only hex
     * (64 chars) for p2tr — otherwise the field-level error message.
     * Blank is reported as "empty" so an untouched row reads
     * differently from a malformed one.
     */
    fun keyError(hex: String, form: MsFormName): String? {
        val trimmed = hex.trim()
        if (trimmed.isEmpty()) return MSG_KEY_EMPTY
        return when (form) {
            MsFormName.P2SH, MsFormName.P2WSH -> compressedKeyError(trimmed)
            MsFormName.P2TR -> xonlyKeyError(trimmed)
        }
    }

    /** The compressed (p2sh/p2wsh) grammar: 66 hex chars, `02`/`03` prefix. */
    private fun compressedKeyError(trimmed: String): String? {
        if (trimmed.length != KEY_HEX_LENGTH) return MSG_KEY_LENGTH
        if (!trimmed.startsWith("02") && !trimmed.startsWith("03")) {
            return MSG_KEY_PREFIX
        }
        if (!KEY_PATTERN.matches(trimmed)) return MSG_KEY_HEX
        return null
    }

    /** The x-only (p2tr) grammar: 64 hex chars, no prefix byte. */
    private fun xonlyKeyError(trimmed: String): String? {
        if (trimmed.length != KEY_HEX_LENGTH_XONLY) return MSG_KEY_LENGTH_XONLY
        if (!XONLY_KEY_PATTERN.matches(trimmed)) return MSG_KEY_HEX
        return null
    }

    /**
     * Indexes of keys that duplicate an earlier row (for
     * highlighting). Duplicate keys block the build (`MsError::
     * DuplicateKey` at the FFI); case differences are normalised —
     * hex is case-insensitive.
     */
    fun duplicateIndexes(keys: List<String>): Set<Int> {
        val seen = HashSet<String>()
        val dups = HashSet<Int>()
        keys.forEachIndexed { idx, key ->
            val normalized = key.trim().lowercase()
            if (normalized.isNotEmpty() && !seen.add(normalized)) {
                dups.add(idx)
            }
        }
        return dups
    }

    /**
     * How many cosigner key rows the create form needs: the full N
     * for a watch-only quorum, N−1 when our own derived key joins
     * (the FFI appends it at the given nonce).
     */
    fun requiredKeyCount(n: Int, ownKeyInQuorum: Boolean): Int =
        if (ownKeyInQuorum) n - 1 else n

    /**
     * The canonical lowercase name of the quorum address form
     * (spec «Multi-sig») —
     * the CLI `--form` spelling and the selector's value. Default is
     * `p2sh` (documented spec decision: R-MS-1 is about N/M, the
     * legacy form is the conservative quorum encoding).
     */
    fun formName(form: MsFormName): String = when (form) {
        MsFormName.P2SH -> "p2sh"
        MsFormName.P2WSH -> "p2wsh"
        MsFormName.P2TR -> "p2tr"
    }

    /**
     * The one-line explanation shown under the form selector: what
     * the choice changes. For p2sh/p2wsh the redeem script is
     * identical and only the address encoding changes; p2tr is the
     * script-path form — a different (tapscript) script and the
     * x-only key encoding.
     */
    fun formHint(form: MsFormName): String = when (form) {
        MsFormName.P2SH ->
            "P2SH quorum: legacy 3… address, scriptSig spend"
        MsFormName.P2WSH ->
            "P2WSH quorum: native bc1q… address, witness spend"
        MsFormName.P2TR ->
            "P2TR quorum: script-path bc1p… address, tapscript (x-only keys)"
    }

    /**
     * The per-row key-field label: the encoding the selected form
     * expects (R-MS-10) — the screens splice it into
     * «Key i (<label>)».
     */
    fun keyFieldLabel(form: MsFormName): String = when (form) {
        MsFormName.P2SH, MsFormName.P2WSH -> "compressed hex pubkey"
        MsFormName.P2TR -> "x-only hex pubkey"
    }

    // Validation messages — pinned by MsQuorumTest so screen copy
    // cannot drift silently.
    const val MSG_N_REQUIRED = "N is required (no default)"
    const val MSG_M_REQUIRED = "M is required (no default)"
    const val MSG_QUORUM_BOUNDS = "Need 1 ≤ M ≤ N ≤ 15"
    const val MSG_KEY_EMPTY = "Key is empty"
    const val MSG_KEY_LENGTH = "Key must be 66 hex characters"
    const val MSG_KEY_LENGTH_XONLY = "Key must be 64 hex characters (x-only)"
    const val MSG_KEY_PREFIX = "Key must start with 02 or 03 (compressed)"
    const val MSG_KEY_HEX = "Key must be hexadecimal"
    const val MSG_DUPLICATE_KEYS = "Duplicate keys in the quorum"
    const val MSG_KEY_COUNT_MISMATCH = "Key count must equal N"
}
