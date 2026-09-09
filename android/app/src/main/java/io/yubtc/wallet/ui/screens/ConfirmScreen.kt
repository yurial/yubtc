package io.yubtc.wallet.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import uniffi.yubtc_core.TxResultRecord
import uniffi.yubtc_core.satoshiToBtc

/**
 * Confirm screen — review the built tx before broadcasting.
 *
 * Reached from `SendScreen` after `makeTransactionMulti` populates
 * `state.lastTx`. The screen shows:
 *
 * - Destination address (truncated).
 * - Amount, fee, cashback.
 * - Txid (full hex).
 * - Raw hex (collapsible / scrollable).
 *
 * "Broadcast" calls [onBroadcast] and waits for `state.lastTxid`
 * to be populated. On success the home / receive screen becomes
 * the next step — for Phase 7 we just stay here and show the
 * confirmed txid.
 */
@Composable
fun ConfirmScreen(
    tx: TxResultRecord,
    txid: String?,
    onBroadcast: () -> Unit,
    onBack: () -> Unit,
) {
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = "Confirm",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Stat("Amount", "${satoshiToBtc(tx.amountSat)} BTC")
                    Stat("Fee", "${satoshiToBtc(tx.feeSat)} BTC")
                    Stat("Cashback", "${satoshiToBtc(tx.cashbackSat)} BTC")
                    Stat("Txid", tx.txidHex)
                    if (txid != null) {
                        Stat("Network txid", txid)
                    }
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Raw hex",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = tx.txHex,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(onClick = onBack, modifier = Modifier.weight(1f)) {
                    Text("Back")
                }
                Button(onClick = onBroadcast, modifier = Modifier.weight(1f)) {
                    Text(if (txid == null) "Broadcast" else "Broadcasted ✓")
                }
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
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}
