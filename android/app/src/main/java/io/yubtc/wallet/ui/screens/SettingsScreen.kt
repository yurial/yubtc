package io.yubtc.wallet.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Settings screen.
 *
 * - **Backend selector** — chip group of [BACKENDS]. Tapping a chip
 *   calls [onBackendChange] which routes through
 *   [io.yubtc.wallet.data.YubtcViewModel.setBackend]. The
 *   currently active backend is highlighted.
 * - **Wipe on leaving app** — phase 9 T3. Toggle that arms the
 *   `LockScheduler` started by `MainActivity`. When OFF, the
 *   wallet stays loaded even when the process is in the
 *   background — "convenience over paranoia" (specs/spec.md «Wipe-on-lock»).
 * - **Auto-wipe delay** — chip group of [IDLE_CHOICES_MIN]. The
 *   minutes field is the only knob the user has over the
 *   scheduler; the production wiring clamps out-of-range values.
 * - **Strict BIP-39 validation** — C8 / R-3 spec.md. Toggle for
 *   the opt-in strict seed-reception mode (full BIP-39 parse +
 *   entropy floor, blocking rejection). Default OFF = the
 *   permissive mode: any non-empty phrase, low entropy only warns
 *   (R-6).
 * - **Address type** — Phase 13. Chip group of [ADDR_TYPE_CHOICES]
 *   (`legacy` / `native` / `taproot`): the receive-address form
 *   used by the next unlock (P2PKH `1…` / P2WPKH `bc1q…` / P2TR
 *   `bc1p…`). Default `native`, mirroring the core and the CLI.
 * - **Lock wallet** — drops the handle and returns to passphrase.
 *
 * Phase 9 adds: confirmations depth slider, "wipe app" panic
 * button, advanced RPC URL override.
 */
@Composable
fun SettingsScreen(
    currentBackend: String,
    wipeOnIdle: Boolean,
    idleMinutes: Int,
    strictBip39: Boolean,
    addrType: String,
    onBackendChange: (String) -> Unit,
    onWipeOnIdleChange: (Boolean) -> Unit,
    onIdleMinutesChange: (Int) -> Unit,
    onStrictBip39Change: (Boolean) -> Unit,
    onAddrTypeChange: (String) -> Unit,
    onLock: () -> Unit,
    onBack: () -> Unit,
) {
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = "Settings",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        text = "Network backend",
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = "Currently active: $currentBackend",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        BACKENDS.forEach { name ->
                            FilterChip(
                                selected = currentBackend == name,
                                onClick = { onBackendChange(name) },
                                label = { Text(name) },
                            )
                        }
                    }
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        text = "Privacy",
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Wipe wallet when leaving the app",
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                            Text(
                                text = "After the wallet sits in the background for the " +
                                    "delay below, the seed is wiped from memory.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Switch(
                            checked = wipeOnIdle,
                            onCheckedChange = onWipeOnIdleChange,
                        )
                    }
                    Text(
                        text = "Auto-wipe delay",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = "Currently: $idleMinutes min",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        IDLE_CHOICES_MIN.forEach { minutes ->
                            FilterChip(
                                selected = idleMinutes == minutes,
                                onClick = { onIdleMinutesChange(minutes) },
                                label = { Text("$minutes min") },
                            )
                        }
                    }
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        text = "Seed",
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Strict BIP-39 validation",
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.onSurface,
                            )
                            Text(
                                text = "Require a valid BIP-39 mnemonic (wordlist + " +
                                    "checksum) and enough distinct words when " +
                                    "unlocking. Off: any non-empty phrase is " +
                                    "accepted; short phrases only warn.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Switch(
                            checked = strictBip39,
                            onCheckedChange = onStrictBip39Change,
                        )
                    }

                    Text(
                        text = "Receive address type",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = "Address form used after the next unlock. " +
                            "Applies on unlock — lock and re-open the " +
                            "wallet to switch the displayed address.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        ADDR_TYPE_CHOICES.forEach { type ->
                            FilterChip(
                                selected = addrType == type.value,
                                onClick = { onAddrTypeChange(type.value) },
                                label = { Text(type.label) },
                            )
                        }
                    }
                }
            }

            Button(onClick = onLock, modifier = Modifier.fillMaxWidth()) {
                Text("Lock wallet")
            }

            OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
                Text("Back")
            }
        }
    }
}

/**
 * Backend names exposed in Settings. Mirrors the names accepted by
 * `core/src/net::get_backend`. `blockchain.info` is the wallet
 * default; tapping the same chip twice is a no-op.
 */
private val BACKENDS = listOf("blockchain.info", "blockstream", "mempool.space")

/**
 * Idle-window choices exposed in Settings. Mirrors the clamp
 * contract on [io.yubtc.wallet.data.SettingsRepository.idleMinutes];
 * only these three values are reachable through the UI.
 */
private val IDLE_CHOICES_MIN = listOf(1, 5, 15)

/**
 * Receive-address forms exposed in Settings (Phase 13). Values
 * mirror the core's `AddrType` / the repository whitelist; labels
 * are the user-facing address shapes.
 */
private val ADDR_TYPE_CHOICES = listOf(
    AddrTypeChoice("legacy", "Legacy (1…)"),
    AddrTypeChoice("native", "Native (bc1q…)"),
    AddrTypeChoice("taproot", "Taproot (bc1p…)"),
)

/** One chip of the address-type group: persisted value + label. */
private data class AddrTypeChoice(val value: String, val label: String)
