package io.yubtc.wallet.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import io.yubtc.wallet.data.Bip21Uri
import io.yubtc.wallet.data.Bip21Uri.Companion.AMOUNT_PATTERN
import qrcode.QRCode

/**
 * Receive screen — shows the wallet's mainnet P2PKH address as a
 * QR code plus a monospace string for manual copy.
 *
 * The QR is rendered with the pure-Kotlin `qrcode-kotlin` library
 * (no Google Play services / no zxing — keeps the wallet fully
 * offline for receive).
 *
 * **BIP-21 (phase 9 T4)** — when the user fills in `amountBtc`,
 * `label`, or `message`, the QR encodes the canonical
 * `bitcoin:<address>?amount=...&label=...&message=...` URI. Empty
 * fields are skipped; a totally empty form falls back to the bare
 * `bitcoin:<address>` form (still a valid BIP-21).
 *
 * The amount field enforces the same decimal grammar
 * (`Bip21Uri.AMOUNT_PATTERN`) the URI builder accepts — the field
 * rejects `-` and any string with more than 8 fractional digits so
 * the user can never construct a URI the builder would refuse.
 *
 * `copyToClipboard` pushes the *URI* (not the bare address) under
 * the "yubtc bip-21" label so a paste into another wallet
 * populates amount + label automatically.
 */
@Composable
fun ReceiveScreen(
    address: String?,
    /** Pre-filled amount the user requested on Send. Survives
     *  recomposition; the user can edit it before generating the
     *  new URI. */
    initialAmountBtc: String? = null,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    var amountText by remember { mutableStateOf(initialAmountBtc.orEmpty()) }
    var label by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }

    val amountBtc = amountText.trim().ifEmpty { null }
    // The QR/clipboard values only update when the inputs parse.
    // An invalid amount (> 8 fractional digits, negative, ...) is
    // gated by `isAmountValid` so the QR stays in sync with what
    // the URI builder would accept.
    val isAmountValid = amountBtc == null ||
        amountBtc.matches(AMOUNT_PATTERN)

    val bip21Text = remember(address, amountBtc, label, message, isAmountValid) {
        if (address.isNullOrBlank() || !isAmountValid) null
        else runCatching {
            Bip21Uri(
                address = address,
                amountBtc = amountBtc,
                label = label.trim().ifEmpty { null },
                message = message.trim().ifEmpty { null },
            ).toUriString()
        }.getOrNull()
    }

    val qrBitmap = remember(bip21Text) {
        if (bip21Text == null) null
        else runCatching {
            // qrcode-kotlin 4.x: builder chain renders to a
            // QRCodeGraphics whose `getBytes()` yields PNG bytes.
            val png = QRCode.ofSquares().build(bip21Text).render().getBytes()
            BitmapFactory.decodeByteArray(png, 0, png.size)
        }.getOrNull()
    }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = "Receive",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
            )

            if (qrBitmap != null) {
                Image(
                    bitmap = qrBitmap.asImageBitmap(),
                    contentDescription = "BIP-21 QR code",
                    modifier = Modifier
                        .size(256.dp)
                        .padding(8.dp),
                )
            }

            Text(
                text = bip21Text ?: address ?: "(wallet not loaded)",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onBackground,
            )

            OutlinedTextField(
                value = amountText,
                onValueChange = { amountText = it },
                label = { Text("Amount (BTC, optional)") },
                singleLine = true,
                isError = !isAmountValid,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = label,
                onValueChange = { label = it },
                label = { Text("Label (optional)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = message,
                onValueChange = { message = it },
                label = { Text("Message (optional)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            OutlinedButton(
                onClick = { bip21Text?.let { copyToClipboard(context, it) } },
                enabled = bip21Text != null,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Copy URI")
            }

            OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
                Text("Back")
            }
        }
    }
}

private fun copyToClipboard(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    clipboard?.setPrimaryClip(ClipData.newPlainText("yubtc bip-21", text))
}
