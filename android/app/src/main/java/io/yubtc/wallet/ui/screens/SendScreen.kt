package io.yubtc.wallet.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
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
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import uniffi.yubtc_core.defaultFeekbSat

/**
 * Send screen — destination + amount + fee + UTXO picker.
 *
 * Flow:
 *
 * 1. User enters destination, amount, picks fee (sat/kB slider)
 *    and confirmations (chip group).
 * 2. "Pick inputs" navigates to `UTXOPickerScreen` (Coin Control).
 *    The picker's selection lives in [YubtcViewModel.selectedUtxos]
 *    so it survives navigation.
 * 3. "Build transaction" calls [onBuild] which routes through
 *    [YubtcViewModel.makeTransactionMultiFromBtc]. The built tx
 *    lands in `state.lastTx`; the screen reacts and navigates to
 *    `confirm`.
 * 4. Confirm screen shows txid / amount / fee / cashback and a
 *    Broadcast button.
 *
 * "Send max" toggles between "drain" (`amountSat = null`) and a
 * numeric amount the user typed.
 *
 * @param address Wallet's own address (shown as the cashback target).
 * @param selectedCount How many UTXOs the picker currently has —
 *   shown above the "Pick inputs" button.
 * @param errorMessage Latest VM error; cleared when the user
 *   changes inputs.
 * @param onBuild Triggered by the "Build transaction" button.
 *   `amountBtc == null` → drain (Send max); otherwise parsed via
 *   `btcToSatoshi` in the VM (so a parse error surfaces as
 *   `errorMessage`, not as an uncaught exception on the UI thread).
 * @param onRequestPayment Triggered by "Request this amount instead"
 *   (phase 9 T4). Receives the amount currently typed in the form,
 *   trimmed, or `null` when the field is empty / Send max is on —
 *   Receive then pre-fills its BIP-21 amount field with it. The
 *   string is passed through verbatim; Receive validates it against
 *   `Bip21Uri.AMOUNT_PATTERN` and refuses to build a URI from an
 *   unparseable value rather than throwing.
 */
@Composable
fun SendScreen(
    address: String?,
    selectedCount: Int,
    errorMessage: String?,
    onBuild: (
        dst: String,
        amountBtc: String?,
        feekbSat: ULong,
        feeSat: ULong,
        confirmations: UInt,
    ) -> Unit,
    onPickInputs: () -> Unit,
    onRequestPayment: (amountBtc: String?) -> Unit,
    onBack: () -> Unit,
) {
    var dst by remember { mutableStateOf("") }
    var amountText by remember { mutableStateOf("") }
    var sendMax by remember { mutableStateOf(false) }
    var feekb by remember { mutableFloatStateOf(defaultFeekbSat().toFloat() / 1000f) }
    var confirmations by remember { mutableStateOf(6u) }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = "Send",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )
            Text(
                text = "Cashback to: ${address ?: "(none)"}",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )

            OutlinedTextField(
                value = dst,
                onValueChange = { dst = it },
                label = { Text("Destination address") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.None,
                    keyboardType = KeyboardType.Text,
                    autoCorrectEnabled = false,
                ),
                modifier = Modifier.fillMaxWidth(),
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = amountText,
                    onValueChange = { amountText = it },
                    label = { Text("Amount (BTC)") },
                    singleLine = true,
                    enabled = !sendMax,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Decimal,
                    ),
                    modifier = Modifier.weight(1f),
                )
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Switch(checked = sendMax, onCheckedChange = { sendMax = it })
                    Text(
                        text = "Send max",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onBackground,
                    )
                }
            }

            Text(
                text = "Fee rate: ${feekb.toInt()} sat/vB (${(feekb * 1000).toInt()} sat/kB)",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )
            Slider(
                value = feekb,
                onValueChange = { feekb = it },
                valueRange = 1f..20f,
                steps = 18,
            )

            Text(
                text = "Confirmations",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(0u, 1u, 6u).forEach { c ->
                    FilterChip(
                        selected = confirmations == c,
                        onClick = { confirmations = c },
                        label = { Text(if (c == 0u) "any" else "$c") },
                    )
                }
            }

            OutlinedButton(onClick = onPickInputs, modifier = Modifier.fillMaxWidth()) {
                Text("Pick inputs: $selectedCount selected")
            }

            Button(
                onClick = {
                    // amountText: null = drain the wallet (Send max);
                    // empty string would let `btcToSatoshi` throw, so
                    // we pass null in that case and let the core
                    // reject with "amount required".
                    val amountBtc: String? = if (sendMax) null else amountText.trim().ifEmpty { null }
                    onBuild(
                        dst.trim(),
                        amountBtc,
                        (feekb * 1000).toULong(),
                        0UL, // feeSat = 0 → run the fee loop
                        confirmations,
                    )
                },
                enabled = dst.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Build transaction")
            }

            OutlinedButton(
                onClick = {
                    onRequestPayment(
                        if (sendMax) null else amountText.trim().ifEmpty { null },
                    )
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Request this amount instead")
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
