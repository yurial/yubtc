package io.yubtc.wallet.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

/**
 * Seed + passphrase entry. The first screen the user sees on cold
 * launch.
 *
 * Behaviour:
 *
 * - The seed field accepts a BIP-39 mnemonic (12 / 15 / 18 / 21 / 24
 *   words separated by single spaces). Validation runs in the
 *   UniFFI core on `unlock`; an invalid seed surfaces the error in
 *   [errorMessage].
 * - The passphrase is entered once and never displayed (masked with
 *   `PasswordVisualTransformation`). Empty passphrase keeps the
 *   legacy `Yubtc` KDF path — bit-for-bit compatible with seeds
 *   generated before BIP-39 passphrase support was added.
 * - "Generate new seed" creates a fresh 12-word BIP-39 mnemonic and
 *   shows it in a card. The user must explicitly accept the seed
 *   (filling the seed field) before it can be used to unlock the
 *   wallet; this prevents accidental loss — the seed is never
 *   persisted to disk in Phase 7.
 *
 * The screen is purely declarative: it forwards the typed values
 * to [onUnlock] / [onGenerateSeed] / [onDismissGenerated] and lets
 * [YubtcNavHost] observe `state.status` to drive navigation.
 *
 * @param onUnlock ViewModel entry point. Receives the seed string
 *   and passphrase. The passphrase is intentionally NOT trimmed —
 *   BIP-39 passphrases can contain leading / trailing spaces. A
 *   first unlock with a low-entropy seed raises the non-blocking
 *   [lowEntropyWarning]; repeating the call with the same seed is
 *   the `Continue` confirmation.
 * @param onGenerateSeed Triggers `YubtcViewModel.generateSeed`. The
 *   resulting mnemonic lands in [generatedSeed].
 * @param onAcceptGenerated Fills the seed field with [generatedSeed]
 *   and dismisses the preview card.
 * @param onDismissGenerated Clears [generatedSeed] without using it.
 * @param generatedSeed Latest preview from [onGenerateSeed], or
 *   `null` when the preview is hidden.
 * @param lowEntropyWarning Pending R-6 entropy warning text, or
 *   `null`. Non-null shows the «Low entropy» card with
 *   `Continue` / `Edit`; the warning never blocks unlock by itself.
 * @param onDismissLowEntropyWarning `Edit`: clears the warning and
 *   returns to input.
 * @param errorMessage Latest error from the ViewModel.
 */
@Composable
fun PassphraseScreen(
    onUnlock: (seed: String, passphrase: String) -> Unit,
    onGenerateSeed: (wordCount: UByte) -> Unit,
    onAcceptGenerated: () -> Unit,
    onDismissGenerated: () -> Unit,
    generatedSeed: String?,
    lowEntropyWarning: String?,
    onDismissLowEntropyWarning: () -> Unit,
    errorMessage: String?,
) {
    var seed by remember { mutableStateOf("") }
    var passphrase by remember { mutableStateOf("") }
    val context = LocalContext.current

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 48.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = "yubtc",
                style = MaterialTheme.typography.displayLarge,
                color = MaterialTheme.colorScheme.primary,
            )
            Text(
                text = "Enter your BIP-39 seed and passphrase.",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onBackground,
            )

            OutlinedTextField(
                value = seed,
                onValueChange = { seed = it },
                label = { Text("Seed (BIP-39 mnemonic)") },
                singleLine = false,
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.None,
                    keyboardType = KeyboardType.Text,
                    autoCorrectEnabled = false,
                ),
                modifier = Modifier.fillMaxWidth(),
            )

            OutlinedTextField(
                value = passphrase,
                onValueChange = { passphrase = it },
                label = { Text("Passphrase (optional)") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                ),
                modifier = Modifier.fillMaxWidth(),
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Button(
                    onClick = {
                        onUnlock(seed.trim(), passphrase)
                    },
                    enabled = seed.isNotBlank(),
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Unlock")
                }
                OutlinedButton(
                    onClick = { onGenerateSeed(12u) },
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Generate")
                }
            }

            if (generatedSeed != null) {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(
                            text = "New seed (write it down before accepting)",
                            style = MaterialTheme.typography.titleLarge,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Text(
                            text = generatedSeed,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            TextButton(
                                onClick = {
                                    copyToClipboard(context, generatedSeed)
                                },
                                modifier = Modifier.weight(1f),
                            ) {
                                Text("Copy")
                            }
                            TextButton(
                                onClick = {
                                    seed = generatedSeed
                                    onAcceptGenerated()
                                },
                                modifier = Modifier.weight(1f),
                            ) {
                                Text("Use")
                            }
                            TextButton(
                                onClick = onDismissGenerated,
                                modifier = Modifier.weight(1f),
                            ) {
                                Text("Dismiss")
                            }
                        }
                    }
                }
            }

            if (lowEntropyWarning != null) {
                // R-6: the entropy warning accompanies acceptance in
                // both reception modes and never blocks unlock —
                // `Continue` repeats the unlock (the ViewModel
                // treats the repeat as the confirmation), `Edit`
                // returns to input.
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(
                            text = "Low entropy",
                            style = MaterialTheme.typography.titleLarge,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Text(
                            text = lowEntropyWarning,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Button(
                                onClick = { onUnlock(seed.trim(), passphrase) },
                                modifier = Modifier.weight(1f),
                            ) {
                                Text("Continue")
                            }
                            OutlinedButton(
                                onClick = onDismissLowEntropyWarning,
                                modifier = Modifier.weight(1f),
                            ) {
                                Text("Edit")
                            }
                        }
                    }
                }
            }

            if (errorMessage != null) {
                Box(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = errorMessage,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
    }
}

/** Copy [text] to the system clipboard under the "yubtc seed" label. */
private fun copyToClipboard(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    clipboard?.setPrimaryClip(ClipData.newPlainText("yubtc seed", text))
}
