package io.yubtc.wallet.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
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
import io.yubtc.wallet.data.MsSendPhase
import qrcode.QRCode
import uniffi.yubtc_core.MsFormName
import uniffi.yubtc_core.PsbtSummaryRecord
import uniffi.yubtc_core.UtxoWithNonce
import uniffi.yubtc_core.defaultFeekbSat
import uniffi.yubtc_core.satoshiToBtc

/**
 * Multi-sig spend screen (Phase 15, route `ms_send`).
 *
 * Contract (spec.md «Принято (2026-09-02): полный surface»): emit a
 * PSBT and accept a PSBT back — the cosigner signing rounds are
 * out-of-band (base64 transport), the screen never orchestrates
 * them. State machine
 * `form → built → awaiting → imported → broadcast`
 * ([MsSendPhase], data-driven; transitions only through the
 * ViewModel's [io.yubtc.wallet.data.MsSendFlow] handlers; FFI
 * refusals land in `errorMessage` without resetting the state).
 *
 * - **form** — quorum editor (same N/M/keys/own-key semantics as
 *   [MsCreateScreen]; N and M have no defaults, R-MS-1), the
 *   SendScreen-style destination/amount/fee/confirmations fields,
 *   and a `utxo_picker`-pattern Coin Control section over the
 *   `ms_unspent` set (ОВ-13: direct `get_utxos` of the quorum
 *   address, nonce = 0 sentinel). Build → `ms_build_psbt` (Creator +
 *   own Signer in one step, ОВ-12).
 * - **built** — the base64 PSBT displayed and shareable (copy + QR);
 *   «Hand off to cosigners» advances to awaiting.
 * - **awaiting** — paste/import field for the combined+finalized
 *   PSBT back.
 * - **imported** — `psbt_decode` preview of the finalized container;
 *   «Broadcast» runs `psbt_extract` + broadcast.
 * - **broadcast** — terminal: `msFinalTxid` displayed; «New spend»
 *   returns to form.
 *
 * «Back to form» is available on every phase without loss of the
 * entered N/M/keys (they are screen-local and survive all
 * transitions).
 */
@Composable
fun MsSendScreen(
    phase: MsSendPhase,
    msUnspent: List<UtxoWithNonce>,
    msSelected: Set<UtxoWithNonce>,
    psbt: String?,
    psbtSummary: PsbtSummaryRecord?,
    builtFeeSat: ULong?,
    importedSummary: PsbtSummaryRecord?,
    finalTxid: String?,
    errorMessage: String?,
    onFetchUtxos: (
        n: UInt,
        m: UInt,
        keys: List<String>,
        nonce: UInt?,
        form: MsFormName,
        confirmations: UInt,
    ) -> Unit,
    onToggleUtxo: (UtxoWithNonce) -> Unit,
    onSelectAllUtxos: () -> Unit,
    onClearUtxos: () -> Unit,
    onBuild: (
        dst: String,
        amountBtc: String,
        n: UInt,
        m: UInt,
        keys: List<String>,
        nonce: UInt?,
        feekbSat: ULong,
        feeSat: ULong,
        form: MsFormName,
    ) -> Unit,
    onMarkAwaiting: () -> Unit,
    onImport: (psbtB64: String) -> Unit,
    onBroadcast: () -> Unit,
    onBackToForm: () -> Unit,
    onBack: () -> Unit,
) {
    // Quorum inputs survive every phase transition (spec: «назад на
    // любом шаге — без потери введённых N/M/ключей»).
    var nText by remember { mutableStateOf("") }
    var mText by remember { mutableStateOf("") }
    var keys by remember { mutableStateOf(listOf("")) }
    var ownKey by remember { mutableStateOf(false) }
    var nonceText by remember { mutableStateOf("") }
    // v0.3 quorum form: default p2sh (documented spec decision), the
    // choice survives phase transitions like the rest of the inputs.
    var form by remember { mutableStateOf(MsFormName.P2SH) }

    // Spend form (SendScreen semantics; amount is required — the
    // quorum build has no drain mode).
    var dst by remember { mutableStateOf("") }
    var amountText by remember { mutableStateOf("") }
    var feekb by remember { mutableFloatStateOf(defaultFeekbSat().toFloat() / 1000f) }
    var confirmations by remember { mutableStateOf(6u) }
    var importText by remember { mutableStateOf("") }

    val n = MsQuorum.parseCount(nText)
    val m = MsQuorum.parseCount(mText)
    val nmError = MsQuorum.quorumError(n, m)
    val nonce = if (ownKey) MsQuorum.parseCount(nonceText) else null
    val duplicateIdx = MsQuorum.duplicateIndexes(keys)
    val requiredKeys = if (n != null) MsQuorum.requiredKeyCount(n, ownKey) else null
    // R-MS-10: the row grammar follows the selected form.
    val keyErrors = keys.map { MsQuorum.keyError(it, form) }
    val keyLabel = MsQuorum.keyFieldLabel(form)
    val quorumComplete = n != null && m != null && nmError == null &&
        requiredKeys != null && keys.size == requiredKeys &&
        keyErrors.all { it == null } && duplicateIdx.isEmpty() &&
        (!ownKey || nonce != null)

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = "Multisig send",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )
            Text(
                text = "Emit a PSBT, collect M signatures, import the finalized PSBT back",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )
            Text(
                text = "Phase: ${phase.name.lowercase()}",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            when (phase) {
                MsSendPhase.FORM -> FormPhase(
                    form = form, onFormChange = { form = it },
                    nText = nText, onNChange = { nText = it },
                    mText = mText, onMChange = { mText = it },
                    nmError = nmError, n = n, m = m,
                    keys = keys, onKeysChange = { keys = it },
                    keyErrors = keyErrors, keyLabel = keyLabel,
                    duplicateIdx = duplicateIdx,
                    ownKey = ownKey, onOwnKeyChange = { ownKey = it },
                    nonceText = nonceText, onNonceChange = { nonceText = it },
                    nonce = nonce,
                    requiredKeys = requiredKeys,
                    dst = dst, onDstChange = { dst = it },
                    amountText = amountText, onAmountChange = { amountText = it },
                    feekb = feekb, onFeekbChange = { feekb = it },
                    confirmations = confirmations,
                    onConfirmationsChange = { confirmations = it },
                    msUnspent = msUnspent, msSelected = msSelected,
                    quorumComplete = quorumComplete,
                    onToggleUtxo = onToggleUtxo,
                    onSelectAllUtxos = onSelectAllUtxos,
                    onClearUtxos = onClearUtxos,
                    onFetchUtxos = { conf ->
                        onFetchUtxos(n!!.toUInt(), m!!.toUInt(), keys.map { it.trim() },
                            if (ownKey) nonce!!.toUInt() else null, form, conf)
                    },
                    onBuild = {
                        onBuild(
                            dst.trim(), amountText.trim(), n!!.toUInt(), m!!.toUInt(),
                            keys.map { it.trim() }, if (ownKey) nonce!!.toUInt() else null,
                            (feekb * 1000).toULong(), 0UL, form,
                        )
                    },
                )
                MsSendPhase.BUILT -> BuiltPhase(
                    psbt = psbt,
                    summary = psbtSummary,
                    feeSat = builtFeeSat,
                    onMarkAwaiting = onMarkAwaiting,
                    onBackToForm = onBackToForm,
                )
                MsSendPhase.AWAITING -> AwaitingPhase(
                    importText = importText,
                    onImportChange = { importText = it },
                    onImport = { onImport(importText) },
                    onBackToForm = onBackToForm,
                )
                MsSendPhase.IMPORTED -> ImportedPhase(
                    summary = importedSummary,
                    onBroadcast = onBroadcast,
                    onBackToForm = onBackToForm,
                )
                MsSendPhase.BROADCAST -> BroadcastPhase(
                    finalTxid = finalTxid,
                    onNewSpend = onBackToForm,
                )
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

/**
 * The form phase: quorum editor + spend fields + the Coin Control
 * section over `ms_unspent`.
 */
@Composable
private fun FormPhase(
    form: MsFormName,
    onFormChange: (MsFormName) -> Unit,
    nText: String,
    onNChange: (String) -> Unit,
    mText: String,
    onMChange: (String) -> Unit,
    nmError: String?,
    n: Int?,
    m: Int?,
    keys: List<String>,
    onKeysChange: (List<String>) -> Unit,
    keyErrors: List<String?>,
    keyLabel: String,
    duplicateIdx: Set<Int>,
    ownKey: Boolean,
    onOwnKeyChange: (Boolean) -> Unit,
    nonceText: String,
    onNonceChange: (String) -> Unit,
    nonce: Int?,
    requiredKeys: Int?,
    dst: String,
    onDstChange: (String) -> Unit,
    amountText: String,
    onAmountChange: (String) -> Unit,
    feekb: Float,
    onFeekbChange: (Float) -> Unit,
    confirmations: UInt,
    onConfirmationsChange: (UInt) -> Unit,
    msUnspent: List<UtxoWithNonce>,
    msSelected: Set<UtxoWithNonce>,
    quorumComplete: Boolean,
    onToggleUtxo: (UtxoWithNonce) -> Unit,
    onSelectAllUtxos: () -> Unit,
    onClearUtxos: () -> Unit,
    onFetchUtxos: (confirmations: UInt) -> Unit,
    onBuild: () -> Unit,
) {
    // Form selector (v0.3): the quorum address form. Default
    // p2sh — the conservative Phase-15 form.
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        FilterChip(
            selected = form == MsFormName.P2SH,
            onClick = { onFormChange(MsFormName.P2SH) },
            label = { Text("P2SH (3…)") },
        )
        FilterChip(
            selected = form == MsFormName.P2WSH,
            onClick = { onFormChange(MsFormName.P2WSH) },
            label = { Text("P2WSH (bc1q…)") },
        )
        FilterChip(
            selected = form == MsFormName.P2TR,
            onClick = { onFormChange(MsFormName.P2TR) },
            label = { Text("P2TR (bc1p…)") },
        )
    }
    Text(
        text = MsQuorum.formHint(form),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = nText,
            onValueChange = onNChange,
            label = { Text("N (total keys)") },
            isError = nText.isNotBlank() && n == null,
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.weight(1f),
        )
        OutlinedTextField(
            value = mText,
            onValueChange = onMChange,
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
            Switch(checked = ownKey, onCheckedChange = onOwnKeyChange)
            Text(
                text = "Our key",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onBackground,
            )
        }
        Text(
            text = if (ownKey) "We co-sign (our key derived at the nonce)"
            else "Watch-only: build disabled (not a participant)",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onBackground,
            modifier = Modifier.weight(1f),
        )
    }
    if (ownKey) {
        OutlinedTextField(
            value = nonceText,
            onValueChange = onNonceChange,
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
                onValueChange = { new -> onKeysChange(keys.toMutableList().also { it[idx] = new }) },
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
            OutlinedButton(
                onClick = { onKeysChange(keys.toMutableList().also { it.removeAt(idx) }) },
            ) {
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
    OutlinedButton(onClick = { onKeysChange(keys + "") }, modifier = Modifier.fillMaxWidth()) {
        Text("Add key")
    }

    OutlinedTextField(
        value = dst,
        onValueChange = onDstChange,
        label = { Text("Destination address") },
        singleLine = true,
        keyboardOptions = KeyboardOptions(
            capitalization = KeyboardCapitalization.None,
            keyboardType = KeyboardType.Text,
            autoCorrectEnabled = false,
        ),
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = amountText,
        onValueChange = onAmountChange,
        label = { Text("Amount (BTC)") },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
        modifier = Modifier.fillMaxWidth(),
    )

    Text(
        text = "Fee rate: ${feekb.toInt()} sat/vB (${(feekb * 1000).toInt()} sat/kB)",
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onBackground,
    )
    Slider(
        value = feekb,
        onValueChange = onFeekbChange,
        valueRange = 1f..20f,
        steps = 18,
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        listOf(0u, 1u, 6u).forEach { c ->
            FilterChip(
                selected = confirmations == c,
                onClick = { onConfirmationsChange(c) },
                label = { Text(if (c == 0u) "any" else "$c") },
            )
        }
    }

    // Coin Control over the quorum address (the utxo_picker pattern
    // embedded in the form phase).
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = "Quorum UTXOs: ${msSelected.size} / ${msUnspent.size} selected",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onBackground,
            modifier = Modifier.weight(1f),
        )
        OutlinedButton(onClick = { onFetchUtxos(confirmations) }) {
            Text("Fetch")
        }
    }
    if (msUnspent.isEmpty()) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = "No UTXOs fetched yet (or none at this confirmations depth).",
                modifier = Modifier.padding(16.dp),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    } else {
        LazyColumn(
            // Bounded height: the phase sections render inside the
            // screen's (non-scrollable) Column, so the list scrolls
            // internally instead of weighing on it.
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(max = 260.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(items = msUnspent, key = { "${it.nonce}:${it.txidHex}:${it.vout}" }) { u ->
                val isSelected = u in msSelected
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onToggleUtxo(u) },
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(checked = isSelected, onCheckedChange = { onToggleUtxo(u) })
                        Column(modifier = Modifier.padding(start = 8.dp)) {
                            Text(
                                text = "${u.txidHex.take(8)}…:${u.vout}",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                            Text(
                                text = "${satoshiToBtc(u.amountSat)} BTC · ${u.confirmations} conf",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
    }
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(onClick = onSelectAllUtxos, modifier = Modifier.weight(1f)) {
            Text("All")
        }
        OutlinedButton(onClick = onClearUtxos, modifier = Modifier.weight(1f)) {
            Text("None")
        }
    }

    Button(
        onClick = onBuild,
        // R-MS-1: no defaults — disabled until N and M are entered;
        // watch-only quorums cannot spend (NotAParticipant at the
        // FFI, refused client-side in the VM).
        enabled = quorumComplete && ownKey && dst.isNotBlank() && amountText.isNotBlank(),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text("Build PSBT")
    }
}

/** BUILT: the PSBT is shareable (copy + QR). */
@Composable
private fun BuiltPhase(
    psbt: String?,
    summary: PsbtSummaryRecord?,
    feeSat: ULong?,
    onMarkAwaiting: () -> Unit,
    onBackToForm: () -> Unit,
) {
    val context = LocalContext.current
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            StatLine("PSBT txid", summary?.txidHex ?: "—")
            StatLine("Inputs", "${summary?.inputs?.size ?: 0}")
            StatLine("Outputs", "${summary?.outputs?.size ?: 0}")
            if (feeSat != null) {
                StatLine("Fee", "${satoshiToBtc(feeSat)} BTC")
            }
            StatLine("Our partial sigs", "${summary?.inputs?.sumOf { it.nPartialSigs.toInt() } ?: 0}")
        }
    }
    if (psbt != null) {
        val qrBitmap = remember(psbt) {
            runCatching {
                val png = QRCode.ofSquares().build(psbt).render().getBytes()
                BitmapFactory.decodeByteArray(png, 0, png.size)
            }.getOrNull()
        }
        if (qrBitmap != null) {
            Image(
                bitmap = qrBitmap.asImageBitmap(),
                contentDescription = "PSBT QR code",
                modifier = Modifier
                    .size(256.dp)
                    .padding(8.dp),
            )
        } else {
            Text(
                text = "PSBT too large for a QR — use Copy instead.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Card(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = psbt,
                modifier = Modifier.padding(16.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
        OutlinedButton(
            onClick = { copyToClipboard(context, psbt) },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Copy PSBT (base64)")
        }
    }
    Button(onClick = onMarkAwaiting, modifier = Modifier.fillMaxWidth()) {
        Text("Hand off to cosigners")
    }
    OutlinedButton(onClick = onBackToForm, modifier = Modifier.fillMaxWidth()) {
        Text("Back to form")
    }
}

/** AWAITING: import the combined+finalized PSBT back. */
@Composable
private fun AwaitingPhase(
    importText: String,
    onImportChange: (String) -> Unit,
    onImport: () -> Unit,
    onBackToForm: () -> Unit,
) {
    Text(
        text = "Waiting for cosigners. Paste the combined+finalized PSBT " +
            "once all M signatures are collected.",
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onBackground,
    )
    OutlinedTextField(
        value = importText,
        onValueChange = onImportChange,
        label = { Text("Finalized PSBT (base64)") },
        keyboardOptions = KeyboardOptions(
            capitalization = KeyboardCapitalization.None,
            keyboardType = KeyboardType.Text,
            autoCorrectEnabled = false,
        ),
        modifier = Modifier.fillMaxWidth(),
    )
    Button(
        onClick = onImport,
        enabled = importText.isNotBlank(),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text("Import PSBT")
    }
    OutlinedButton(onClick = onBackToForm, modifier = Modifier.fillMaxWidth()) {
        Text("Back to form")
    }
}

/** IMPORTED: decode preview of the finalized container. */
@Composable
private fun ImportedPhase(
    summary: PsbtSummaryRecord?,
    onBroadcast: () -> Unit,
    onBackToForm: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            StatLine("PSBT txid", summary?.txidHex ?: "—")
            StatLine("Inputs", "${summary?.inputs?.size ?: 0}")
            StatLine("Outputs", "${summary?.outputs?.size ?: 0}")
            StatLine(
                "Fee",
                summary?.feeSat?.let { "${satoshiToBtc(it)} BTC" } ?: "— (no UTXO data)",
            )
            StatLine(
                "Finalized inputs",
                "${summary?.inputs?.count { it.finalized } ?: 0}",
            )
        }
    }
    Button(onClick = onBroadcast, modifier = Modifier.fillMaxWidth()) {
        Text("Extract & broadcast")
    }
    OutlinedButton(onClick = onBackToForm, modifier = Modifier.fillMaxWidth()) {
        Text("Back to form")
    }
}

/** BROADCAST: terminal phase — the network txid. */
@Composable
private fun BroadcastPhase(
    finalTxid: String?,
    onNewSpend: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            StatLine("Broadcasted ✓", "")
            StatLine("Network txid", finalTxid ?: "—")
        }
    }
    Button(onClick = onNewSpend, modifier = Modifier.fillMaxWidth()) {
        Text("New spend")
    }
}

@Composable
private fun StatLine(label: String, value: String) {
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
    clipboard?.setPrimaryClip(ClipData.newPlainText("yubtc psbt", text))
}
