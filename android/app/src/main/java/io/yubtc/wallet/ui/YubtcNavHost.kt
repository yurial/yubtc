package io.yubtc.wallet.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import io.yubtc.wallet.data.YubtcViewModel
import io.yubtc.wallet.data.WalletStatus
import io.yubtc.wallet.ui.screens.ConfirmScreen
import io.yubtc.wallet.ui.screens.HomeScreen
import io.yubtc.wallet.ui.screens.MsCreateScreen
import io.yubtc.wallet.ui.screens.MsSendScreen
import io.yubtc.wallet.ui.screens.PassphraseScreen
import io.yubtc.wallet.ui.screens.ReceiveScreen
import io.yubtc.wallet.ui.screens.SendScreen
import io.yubtc.wallet.ui.screens.SettingsScreen
import io.yubtc.wallet.ui.screens.UtxoPickerScreen

/**
 * Single-activity navigation host.
 *
 * The graph has nine destinations:
 *
 * - **passphrase** — entry point.
 * - **home** — once unlocked.
 * - **send** — destination + amount + fee form. "Pick inputs" goes
 *   to `utxo_picker`. After a successful build, the LaunchedEffect
 *   navigates to `confirm`.
 * - **utxo_picker** — Coin Control list. Lives on the Send flow
 *   back-stack; selection is in [YubtcViewModel.selectedUtxos].
 * - **confirm** — review the built tx; Broadcast button posts it.
 * - **receive / settings** — direct children of home. `receive`
 *   takes an optional `?amount=<btc>` query argument: Home reaches it
 *   bare (`receive`), while Send's "Request this amount instead"
 *   button carries the typed amount over so the BIP-21 URI is
 *   pre-filled.
 * - **ms_create / ms_send** — multi-sig (Phase 15) children of home:
 *   the quorum address form and the PSBT state machine
 *   (`form → built → awaiting → imported → broadcast`, all phases on
 *   the single `ms_send` destination, data-driven through
 *   [io.yubtc.wallet.data.MsSendPhase]).
 *
 * Status-driven navigation handles Locked ⇄ Loaded transitions;
 * data-driven navigation handles Send → Confirm.
 */
@Composable
fun YubtcNavHost(
    vm: YubtcViewModel,
    navController: NavHostController = rememberNavController(),
) {
    val state by vm.state.collectAsState()

    // Cold launch: pick the right start destination from current
    // status. After that, status changes drive navigation through
    // the LaunchedEffect below.
    val startDestination = if (state.status == WalletStatus.Loaded) "home" else "passphrase"

    // Status → navigation. Flipping Locked ⇄ Loaded moves the
    // graph between passphrase and home.
    LaunchedEffect(state.status) {
        val target = if (state.status == WalletStatus.Loaded) "home" else "passphrase"
        val current = navController.currentDestination?.route
        if (current != target) {
            navController.navigate(target) {
                popUpTo(0) { inclusive = true }
            }
        }
    }

    // Send → Confirm. After `makeTransactionMulti` lands in
    // `lastTx`, navigate forward. Cleared after broadcast so the
    // user can build a new tx without auto-pushing again.
    LaunchedEffect(state.lastTx) {
        if (state.lastTx != null) {
            val current = navController.currentDestination?.route
            if (current == "send" || current == "utxo_picker") {
                navController.navigate("confirm") {
                    popUpTo("send")
                }
            }
        }
    }

    NavHost(navController = navController, startDestination = startDestination) {
        composable("passphrase") {
            PassphraseScreen(
                onUnlock = vm::unlock,
                onGenerateSeed = vm::generateSeed,
                onAcceptGenerated = vm::dismissGeneratedSeed,
                onDismissGenerated = vm::dismissGeneratedSeed,
                generatedSeed = state.generatedSeed,
                lowEntropyWarning = state.lowEntropyWarning,
                onDismissLowEntropyWarning = vm::dismissLowEntropyWarning,
                errorMessage = state.errorMessage,
            )
        }
        composable("home") {
            HomeScreen(
                address = state.address,
                addressInfo = state.addressInfo,
                onRefresh = { vm.refreshAll() },
                onSendTab = { navController.navigate("send") },
                onReceiveTab = { navController.navigate("receive") },
                onSettingsTab = { navController.navigate("settings") },
                onMsCreateTab = { navController.navigate("ms_create") },
                onMsSendTab = { navController.navigate("ms_send") },
                onLock = { vm.lock() },
            )
        }
        composable("send") {
            SendScreen(
                address = state.cashbackAddr ?: state.address,
                selectedCount = state.selectedUtxos.size,
                errorMessage = state.errorMessage,
                onBuild = { dst, amountBtc, feekb, fee, conf ->
                    vm.makeTransactionMultiFromBtc(
                        dst = dst,
                        amountBtc = amountBtc,
                        feekbSat = feekb,
                        feeSat = fee,
                        confirmations = conf,
                        selected = vm.selectedAsSources(),
                    )
                },
                onPickInputs = { navController.navigate("utxo_picker") },
                onRequestPayment = { amountBtc ->
                    // Phase 9 T4: carry the Send-side amount into the
                    // Receive BIP-21 form. The value is a decimal
                    // string (digits + `.`) so it needs no escaping;
                    // an empty amount navigates to the bare route.
                    navController.navigate(
                        if (amountBtc == null) "receive" else "receive?amount=$amountBtc",
                    )
                },
                onBack = { navController.popBackStack() },
            )
        }
        composable("utxo_picker") {
            UtxoPickerScreen(
                unspent = state.unspent,
                selected = state.selectedUtxos,
                onToggle = vm::toggleUtxo,
                onSelectAll = vm::selectAllUtxos,
                onClear = vm::clearUtxoSelection,
                onAuto = { vm.autoPick(null) },
                onRefresh = { vm.allUnspent() },
                onConfirm = { navController.popBackStack() },
                onBack = { navController.popBackStack() },
            )
        }
        composable("confirm") {
            val tx = state.lastTx
            if (tx != null) {
                ConfirmScreen(
                    tx = tx,
                    txid = state.lastTxid,
                    onBroadcast = { vm.broadcast(tx.txHex) },
                    onBack = {
                        // Go back to home; clear the built tx so a
                        // subsequent build on Send doesn't auto-
                        // navigate again.
                        vm.clearLastTx()
                        navController.popBackStack(route = "home", inclusive = false)
                    },
                )
            }
        }
        composable("ms_create") {
            MsCreateScreen(
                msAddress = state.msAddress,
                errorMessage = state.errorMessage,
                onCreate = { n, m, keys, nonce, form ->
                    vm.msCreateAddress(n, m, keys, nonce, form)
                },
                onBack = { navController.popBackStack() },
            )
        }
        composable("ms_send") {
            MsSendScreen(
                phase = state.msPhase,
                msUnspent = state.msUnspent,
                msSelected = state.msSelectedUtxos,
                psbt = state.msPsbt,
                psbtSummary = state.msPsbtSummary,
                builtFeeSat = state.msBuiltFeeSat,
                importedSummary = state.msImportedSummary,
                finalTxid = state.msFinalTxid,
                errorMessage = state.errorMessage,
                onFetchUtxos = { n, m, keys, nonce, form, conf ->
                    vm.msFetchUnspent(n, m, keys, nonce, form, conf)
                },
                onToggleUtxo = vm::msToggleUtxo,
                onSelectAllUtxos = vm::msSelectAllUtxos,
                onClearUtxos = vm::msClearUtxoSelection,
                onBuild = { dst, amountBtc, n, m, keys, nonce, feekb, fee, form ->
                    vm.msBuildPsbt(
                        dst = dst,
                        amountBtc = amountBtc,
                        n = n,
                        m = m,
                        keys = keys,
                        nonce = nonce,
                        feekbSat = feekb,
                        feeSat = fee,
                        form = form,
                    )
                },
                onMarkAwaiting = vm::msMarkAwaiting,
                onImport = vm::msImportPsbt,
                onBroadcast = vm::msBroadcastFinalized,
                onBackToForm = vm::msBackToForm,
                onBack = { navController.popBackStack() },
            )
        }
        composable(
            route = "receive?amount={amount}",
            arguments = listOf(
                navArgument("amount") {
                    type = NavType.StringType
                    nullable = true
                    defaultValue = null
                },
            ),
        ) { entry ->
            ReceiveScreen(
                address = state.address,
                initialAmountBtc = entry.arguments?.getString("amount"),
                onBack = { navController.popBackStack() },
            )
        }
        composable("settings") {
            SettingsScreen(
                currentBackend = state.currentBackend,
                wipeOnIdle = state.wipeOnIdle,
                idleMinutes = state.idleMinutes,
                strictBip39 = state.strictBip39,
                addrType = state.addrType,
                onBackendChange = { vm.setBackend(it) },
                onWipeOnIdleChange = { vm.setWipeOnIdle(it) },
                onIdleMinutesChange = { vm.setIdleMinutes(it) },
                onStrictBip39Change = { vm.setStrictBip39(it) },
                onAddrTypeChange = { vm.setAddrType(it) },
                onLock = { vm.lock() },
                onBack = { navController.popBackStack() },
            )
        }
    }
}
