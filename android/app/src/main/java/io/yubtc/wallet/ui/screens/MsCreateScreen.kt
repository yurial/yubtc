package io.yubtc.wallet.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import io.yubtc.wallet.data.MsQuorum
import qrcode.QRCode
import uniffi.yubtc_core.MsAddressRecord
import uniffi.yubtc_core.MsFormName

/**
 * Multi-sig quorum address screen (Phase 15, route `ms_create`).
 *
 * Form:
 *
 * - `N` and `M` — **required fields without defaults** (R-MS-1):
 *   both start empty and the Create button stays disabled until
 *   both are entered; the client check `1 ≤ M ≤ N ≤ 15` (R-MS-2,
 *   [MsQuorum.quorumError]) mirrors the authoritative
 *   `MsError::QuorumBounds`.
 * - Key list editor: exactly N pubkeys in the selected form's
 *   encoding (R-MS-3/R-MS-10: compressed hex for p2sh/p2wsh,
 *   x-only hex for p2tr) via [MsQuorum.keyError] per row; duplicates
 *   are highlighted and block the build ([MsQuorum.duplicateIndexes]
 *   — the FFI refuses with `MsError::DuplicateKey`). With «Our key in
 *   quorum» ON only N−1 cosigner rows are needed — the handle appends
 *   the own legacy-form key derived at the given nonce (R-MS-6,
 *   ОВ-10).
 * - «Our key in quorum» OFF = watch-only create: fully offline, no
 *   seed involved.
 * - Form selector (v0.3, ОВ-19): `p2sh` (`3…`, the Phase-15 default),
 *   `p2wsh` (`bc1q…`, bech32 v0 / SHA-256) or `p2tr` (`bc1p…`,
 *   P2TR script-path — CHECKSIGADD tapscript, x-only keys). Default
 *   `p2sh` — the documented spec decision.
 *
 * Result ([io.yubtc.wallet.data.YubtcState.msAddress]): the quorum
 * address in the selected form + redeem script hex (the tapscript
 * for p2tr) + the p2tr witness material (`internal`/`control`) + QR
 * of the address through the existing `qrcode-kotlin` stack
 * (256×256, like ReceiveScreen). Errors land in the VM's
 * `errorMessage`.
 */
@Composable
fun MsCreateScreen(
    msAddress: MsAddressRecord?,
    errorMessage: String?,
    onCreate: (n: UInt, m: UInt, keys: List<String>, nonce: UInt?, form: MsFormName) -> Unit,
    onBack: () -> Unit,
) {
    // R-MS-1: N and M start EMPTY — no defaults anywhere. The form
    // selector DOES default (p2sh) — the documented spec decision.
    var nText by remember { mutableStateOf("") }
    var mText by remember { mutableStateOf("") }
    var keys by remember { mutableStateOf(listOf("")) }
    var ownKey by remember { mutableStateOf(false) }
    var nonceText by remember { mutableStateOf("") }
    var form by remember { mutableStateOf(MsFormName.P2SH) }

    val n = MsQuorum.parseCount(nText)
    val m = MsQuorum.parseCount(mText)
    val nmError = MsQuorum.quorumError(n, m)
    val nonce = if (ownKey) MsQuorum.parseCount(nonceText) else null
    val duplicateIdx = MsQuorum.duplicateIndexes(keys)
    val requiredKeys = if (n != null) MsQuorum.requiredKeyCount(n, ownKey) else null
    // R-MS-10: the row grammar follows the selected form.
    val keyErrors = keys.map { MsQuorum.keyError(it, form) }
    val keyLabel = MsQuorum.keyFieldLabel(form)
    val keysComplete = requiredKeys != null &&
        keys.size == requiredKeys &&
        keyErrors.all { it == null } &&
        duplicateIdx.isEmpty()

    val canCreate = n != null && m != null && nmError == null && keysComplete &&
        (!ownKey || nonce != null)

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = "Multisig create",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )
            Text(
                text = "Quorum address (m-of-n, BIP-67 sorted)",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )

            // Form selector (v0.3): the quorum address form.
            // Default p2sh — the conservative Phase-15 form.
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = form == MsFormName.P2SH,
                    onClick = { form = MsFormName.P2SH },
                    label = { Text("P2SH (3…)") },
                )
                FilterChip(
                    selected = form == MsFormName.P2WSH,
                    onClick = { form = MsFormName.P2WSH },
                    label = { Text("P2WSH (bc1q…)") },
                )
                FilterChip(
                    selected = form == MsFormName.P2TR,
                    onClick = { form = MsFormName.P2TR },
                    label = { Text("P2TR (bc1p…)") },
                )
            }
            Text(
                text = MsQuorum.formHint(form),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(
                    value = nText,
                    onValueChange = { nText = it },
                    label = { Text("N (total keys)") },
                    isError = nText.isNotBlank() && n == null,
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.weight(1f),
                )
                OutlinedTextField(
                    value = mText,
                    onValueChange = { mText = it },
                    label = { Text("M (signatures)") },
                    isError = mText.isNotBlank() && m == null,
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.weight(1f),
                )
            }
            if (nmError != null && n != null && m != null) {
                Text(
                    text = nmError,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Switch(checked = ownKey, onCheckedChange = { ownKey = it })
                    Text(
                        text = "Our key",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onBackground,
                    )
                }
                Text(
                    text = if (ownKey) {
                        "Our key joins the quorum (derived at the nonce)"
                    } else {
                        "Watch-only create (offline, no seed)"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onBackground,
                    modifier = Modifier.weight(1f),
                )
            }
            if (ownKey) {
                OutlinedTextField(
                    value = nonceText,
                    onValueChange = { nonceText = it },
                    label = { Text("Nonce (our key derivation)") },
                    isError = nonceText.isNotBlank() && nonce == null,
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            Text(
                text = "Cosigner keys" +
                    (requiredKeys?.let { " (${"%d of %d".format(keys.size, it)})" } ?: ""),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onBackground,
            )
            keys.forEachIndexed { idx, key ->
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    OutlinedTextField(
                        value = key,
                        onValueChange = { new -> keys = keys.toMutableList().also { it[idx] = new } },
                        label = { Text("Key ${idx + 1} ($keyLabel)") },
                        isError = keyErrors[idx] != null || idx in duplicateIdx,
                        supportingText = {
                            val msg = when {
                                idx in duplicateIdx -> MsQuorum.MSG_DUPLICATE_KEYS
                                else -> keyErrors[idx]
                            }
                            if (msg != null) Text(msg)
                        },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(
                            capitalization = KeyboardCapitalization.None,
                            keyboardType = KeyboardType.Text,
                            autoCorrectEnabled = false,
                        ),
                        modifier = Modifier.weight(1f),
                    )
                    OutlinedButton(onClick = { keys = keys.toMutableList().also { it.removeAt(idx) } }) {
                        Text("✕")
                    }
                }
            }
            if (requiredKeys != null && keys.size != requiredKeys) {
                Text(
                    text = MsQuorum.MSG_KEY_COUNT_MISMATCH,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            OutlinedButton(onClick = { keys = keys + "" }, modifier = Modifier.fillMaxWidth()) {
                Text("Add key")
            }

            Button(
                onClick = {
                    onCreate(
                        n!!.toUInt(),
                        m!!.toUInt(),
                        keys.map { it.trim() },
                        if (ownKey) nonce!!.toUInt() else null,
                        form,
                    )
                },
                enabled = canCreate,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Create quorum address")
            }

            msAddress?.let { record ->
                val qrBitmap = remember(record.address) {
                    runCatching {
                        val png = QRCode.ofSquares().build(record.address).render().getBytes()
                        BitmapFactory.decodeByteArray(png, 0, png.size)
                    }.getOrNull()
                }
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        if (qrBitmap != null) {
                            Image(
                                bitmap = qrBitmap.asImageBitmap(),
                                contentDescription = "Quorum address QR code",
                                modifier = Modifier
                                    .size(256.dp)
                                    .padding(8.dp),
                            )
                        }
                        Stat("Address", record.address)
                        // redeemScriptHex carries the canonical
                        // redeem script — the tapscript itself for
                        // p2tr (field name stable, spec «FFI»).
                        Stat("Redeem script", record.redeemScriptHex)
                        // p2tr witness material: the NUMS internal
                        // key and the 33-byte control block (null
                        // for p2sh/p2wsh).
                        record.internalKeyHex?.let {
                            Stat("Internal key (NUMS)", it)
                        }
                        record.controlBlockHex?.let {
                            Stat("Control block", it)
                        }
                        val context = LocalContext.current
                        OutlinedButton(onClick = { copyToClipboard(context, record.address) }) {
                            Text("Copy address")
                        }
                    }
                }
            }

            OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
                Text("Back")
            }

            if (errorMessage != null) {
                Text(
                    text = errorMessage,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

@Composable
private fun Stat(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

private fun copyToClipboard(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    clipboard?.setPrimaryClip(ClipData.newPlainText("yubtc quorum address", text))
}
