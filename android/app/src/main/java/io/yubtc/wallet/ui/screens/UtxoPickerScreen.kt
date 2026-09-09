package io.yubtc.wallet.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import uniffi.yubtc_core.UtxoWithNonce
import uniffi.yubtc_core.satoshiToBtc

/**
 * Coin Control UTXO picker.
 *
 * Mirrors the CLI `send -i` TUI: list of unspent outputs with a
 * per-row checkbox, plus "All" / "Auto" / "None" / "Confirm"
 * controls.
 *
 * "Auto" runs the Rust `defaultSelection` greedy picker against the
 * cached [unspent] for the user's target amount and replaces the
 * current selection with the result. "All" picks every UTXO.
 * "None" clears the selection.
 *
 * The selection lives in [YubtcViewModel.selectedUtxos] (a
 * [Set] of [UtxoWithNonce]). Each [UtxoWithNonce] already
 * carries the BIP-44 `nonce` of its owning address, so we don't
 * need a separate `SelectedSource` type — the picker keeps
 * [UtxoWithNonce]s and the VM converts to [SelectedSource] at
 * build time (see [YubtcViewModel.selectedAsSources]).
 *
 * On confirm the user navigates back to SendScreen and the Send
 * screen reads the same set.
 *
 * Empty state: if [unspent] is empty the screen shows "no UTXOs"
 * and disables confirm. The picker does not change selection on
 * entry — calling it doesn't override the user's previous pick
 * until they toggle a row.
 */
@Composable
fun UtxoPickerScreen(
    unspent: List<UtxoWithNonce>,
    selected: Set<UtxoWithNonce>,
    onToggle: (UtxoWithNonce) -> Unit,
    onSelectAll: () -> Unit,
    onClear: () -> Unit,
    onAuto: () -> Unit,
    onRefresh: () -> Unit,
    onConfirm: () -> Unit,
    onBack: () -> Unit,
) {
    // Fetch on entry; the user expects the picker to reflect the
    // latest wallet view.
    LaunchedEffect(Unit) { onRefresh() }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "Pick inputs",
                    style = MaterialTheme.typography.headlineMedium,
                    color = MaterialTheme.colorScheme.onBackground,
                )
                Text(
                    text = "${selected.size} / ${unspent.size} selected",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onBackground,
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(onClick = onSelectAll, modifier = Modifier.weight(1f)) {
                    Text("All")
                }
                OutlinedButton(onClick = onAuto, modifier = Modifier.weight(1f)) {
                    Text("Auto")
                }
                OutlinedButton(onClick = onClear, modifier = Modifier.weight(1f)) {
                    Text("None")
                }
            }

            if (unspent.isEmpty()) {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = "No UTXOs available at this confirmations depth.",
                        modifier = Modifier.padding(16.dp),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(items = unspent, key = { "${it.nonce}:${it.txidHex}:${it.vout}" }) { u ->
                        val isSelected = u in selected
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onToggle(u) },
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Checkbox(
                                    checked = isSelected,
                                    onCheckedChange = { onToggle(u) },
                                )
                                Column(
                                    modifier = Modifier
                                        .weight(1f)
                                        .padding(start = 8.dp),
                                ) {
                                    Text(
                                        text = "${u.nonce}# · ${u.txidHex.take(8)}…:${u.vout}",
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

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(onClick = onBack, modifier = Modifier.weight(1f)) {
                    Text("Cancel")
                }
                Button(
                    onClick = onConfirm,
                    enabled = selected.isNotEmpty(),
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Confirm")
                }
            }
        }
    }
}