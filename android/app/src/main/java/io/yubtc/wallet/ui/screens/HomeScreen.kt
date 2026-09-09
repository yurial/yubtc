package io.yubtc.wallet.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import uniffi.yubtc_core.satoshiToBtc

/**
 * Top-level landing screen once a wallet is unlocked.
 *
 * Layout:
 *
 * - Big balance figure (`finalBalance` from `addressInfo()`).
 * - Total received + tx count below.
 * - Address shown as monospace.
 * - Refresh button + auto-refresh on first compose.
 * - Send / Receive / Settings / Lock buttons.
 *
 * The balance is fetched from the wallet's P2PKH address only —
 * single-address v1 wallet. The screen calls
 * [YubtcViewModel.refreshAll] on first compose and whenever the
 * user taps "Refresh".
 *
 * @param address Mainnet P2PKH address from the loaded wallet, or
 *   `null` if the VM hasn't yet derived one.
 * @param addressInfo Latest balance snapshot from `addressInfo()`,
 *   `null` until the first refresh resolves.
 * @param onRefresh Wired to the refresh button and the
 *   first-compose LaunchedEffect.
 * @param onSendTab Navigate to the Send screen.
 * @param onReceiveTab Navigate to the Receive screen.
 * @param onSettingsTab Navigate to the Settings screen.
 * @param onMsCreateTab Navigate to the multi-sig quorum address
 *   form (Phase 15).
 * @param onMsSendTab Navigate to the multi-sig PSBT spend flow
 *   (Phase 15).
 * @param onLock Drop the wallet handle and return to passphrase.
 */
@Composable
fun HomeScreen(
    address: String?,
    addressInfo: uniffi.yubtc_core.AddressInfoRecord?,
    onRefresh: () -> Unit,
    onSendTab: () -> Unit,
    onReceiveTab: () -> Unit,
    onSettingsTab: () -> Unit,
    onMsCreateTab: () -> Unit,
    onMsSendTab: () -> Unit,
    onLock: () -> Unit,
) {
    // Refresh once on first compose. Keyed on Unit so it only runs
    // when this destination enters the composition tree.
    LaunchedEffect(Unit) { onRefresh() }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = "Wallet",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        text = "Balance",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = if (addressInfo != null) {
                            "${satoshiToBtc(addressInfo.finalBalanceSat)} BTC"
                        } else {
                            "—"
                        },
                        style = MaterialTheme.typography.displayLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    if (addressInfo != null) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(
                                text = "Received: ${satoshiToBtc(addressInfo.totalReceivedSat)} BTC",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Text(
                                text = "${addressInfo.nTx} tx",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }

            Box(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = address ?: "(no address)",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onBackground,
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Button(onClick = onSendTab, modifier = Modifier.weight(1f)) {
                    Text("Send")
                }
                Button(onClick = onReceiveTab, modifier = Modifier.weight(1f)) {
                    Text("Receive")
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Button(onClick = onSettingsTab, modifier = Modifier.weight(1f)) {
                    Text("Settings")
                }
                OutlinedButton(onClick = onLock, modifier = Modifier.weight(1f)) {
                    Text("Lock")
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(onClick = onMsCreateTab, modifier = Modifier.weight(1f)) {
                    Text("Ms create")
                }
                OutlinedButton(onClick = onMsSendTab, modifier = Modifier.weight(1f)) {
                    Text("Ms send")
                }
            }

            OutlinedButton(onClick = onRefresh, modifier = Modifier.fillMaxWidth()) {
                Text("Refresh balance")
            }
        }
    }
}
