//! UTXO selection logic — ported from `yubtc-python/src/yubtc/select.py`.
//!
//! These functions are pure (no I/O, no backend), which keeps them
//! unit-testable without spinning up a TUI. The TUI in [`crate::tui`]
//! drives them; `send --interactive` calls them through the TUI's
//! selection loop.

use yubtc_core::misc::{TAddress, TNonce, TSatoshi};
use yubtc_core::wallet::{Source, TPrivKey, Utxo};

/// `(TPrivKey, Vec<Utxo>)` — one address's unspent outputs, used as the
/// unit the selection loop iterates over.
///
/// Mirrors `yubtc-python`'s `sources: list[(TPrivKey, list[utxo])]`.
pub type SelectedUtxo = (TPrivKey, Utxo);

/// Greedy default: smallest set from earliest addresses that meets
/// `target`. `target = None` selects everything (drain mode).
///
/// Deterministic — given the same `sources` and `target`, produces the
/// same selection. Walks sources and UTXOs in their natural order
/// (insertion / scan order).
pub fn default_selection(sources: &[Source], target: Option<TSatoshi>) -> Vec<bool> {
    let mut selected = vec![false; sources.len()];
    if sources.is_empty() {
        return selected;
    }
    let mut total: u64 = 0;
    let target_sat = target.map(|t| t.get());
    for (i, source) in sources.iter().enumerate() {
        // No pre-iteration target check is needed: `total` only
        // changes inside this loop, and the post-add check below
        // breaks on the very condition a top-of-loop check would
        // re-test (a redundant top check is provably dead code).
        selected[i] = true;
        // Note: each Source is a single address with a Vec<Utxo>;
        // selecting the source means picking all its UTXOs.
        let source_total: u64 = source.unspent.iter().map(|u| u.amount).sum();
        total = total.saturating_add(source_total);
        if target_sat.is_some_and(|t| total >= t) {
            break;
        }
    }
    selected
}

/// Sum the amounts of all UTXOs marked in `selected`.
///
/// `selected` is parallel to `sources` (one bool per source). All UTXOs
/// of a selected source are counted.
pub fn compute_total(sources: &[Source], selected: &[bool]) -> u64 {
    sources
        .iter()
        .zip(selected.iter())
        .filter(|(_, s)| **s)
        .flat_map(|(src, _)| src.unspent.iter())
        .map(|u| u.amount)
        .sum()
}

// --- Rough size / fee constants --------------------------------------

/// Tx overhead in bytes (version + locktime + in/out counts).
pub const TX_OVERHEAD_BYTES: usize = 10;

/// Average P2PKH input size (DER sig + compressed pubkey + push op +
/// txin scaffolding).
pub const P2PKH_INPUT_BYTES: usize = 148;

/// Average P2PKH output size (amount + script length + P2PKH script).
pub const P2PKH_OUTPUT_BYTES: usize = 34;

/// Rough estimate of a P2PKH-only tx size in bytes.
pub fn estimate_tx_size(num_inputs: usize, num_outputs: usize) -> usize {
    TX_OVERHEAD_BYTES + P2PKH_INPUT_BYTES * num_inputs + P2PKH_OUTPUT_BYTES * num_outputs
}

/// Number of outputs: 1 (dst only) or 2 (dst + cashback).
pub fn count_outputs(total: u64, target: Option<TSatoshi>, fee: TSatoshi) -> usize {
    if let Some(t) = target {
        if total <= t.get() + fee.get() {
            1
        } else {
            2
        }
    } else {
        1
    }
}

/// `(fee, size_in_bytes)` reflecting the current selection.
///
/// When `fee` is non-zero, it's returned unchanged — the operator
/// pinned it. Otherwise the fee is computed from the estimated size
/// and `feekb`.
pub fn compute_fee_and_size(
    num_inputs: usize,
    total: u64,
    target: Option<TSatoshi>,
    fee: TSatoshi,
    feekb: TSatoshi,
) -> (TSatoshi, usize) {
    let n_out = count_outputs(total, target, fee);
    let size = estimate_tx_size(num_inputs, n_out);
    let fee_sat = if fee.get() > 0 {
        fee.get()
    } else {
        (size as u64) * feekb.get() / 1000
    };
    (TSatoshi::new(fee_sat), size)
}

/// Materialise a `selected: &[bool]` mask into the flat list of
/// `(TPrivKey, Utxo)` pairs that the wallet consumes.
pub fn materialise(sources: &[Source], selected: &[bool]) -> Vec<SelectedUtxo> {
    let mut result = Vec::new();
    for (src, sel) in sources.iter().zip(selected.iter()) {
        if *sel {
            for u in &src.unspent {
                result.push((src.privkey.clone(), u.clone()));
            }
        }
    }
    result
}

// --- helpers for tests / UI -----------------------------------------

/// Identifier for one UTXO in a wallet's source list: `(nonce, vout)`.
///
/// Used by the TUI to mark/unmark selections without juggling
/// `TPrivKey` clones through the event loop.
pub type Marker = (TNonce, u32);

pub fn markers(sources: &[Source]) -> Vec<Marker> {
    sources
        .iter()
        .flat_map(|s| s.unspent.iter().map(|u| (s.privkey.nonce, u.vout)))
        .collect()
}

/// Map a `(nonce, vout)` marker to its address (for the status line).
pub fn address_for(sources: &[Source], marker: Marker) -> Option<TAddress> {
    sources
        .iter()
        .find(|s| s.privkey.nonce == marker.0)
        .map(|s| s.privkey.get_address())
}

#[cfg(test)]
mod tests {
    //! Tests for the CLI's pure UTXO-selection helpers.
    //!
    //! These mirror the behaviour of `yubtc-python/src/yubtc/select.py`
    //! so the Coin Control TUI is deterministic regardless of language.

    use yubtc_core::kdf::KdfAlgo;
    use yubtc_core::misc::{TAddress, TNonce, TPassphrase, TSatoshi};
    use yubtc_core::wallet::{Source, TPrivKey, Utxo};

    use super::{
        address_for, compute_fee_and_size, compute_total, count_outputs, default_selection,
        estimate_tx_size, markers, materialise, Marker,
    };

    fn utxo(amount: u64, vout: u32) -> Utxo {
        Utxo {
            txid: [vout as u8; 32],
            vout,
            amount,
            script_pubkey: vec![0x76, 0xa9, 0x14],
            confirmations: 6,
        }
    }

    fn pk(nonce: u32) -> TPrivKey {
        TPrivKey::new(
            &yubtc_core::misc::TSeed::new(format!("seed nonce={nonce}")),
            TNonce::new(nonce),
            &TPassphrase::EMPTY,
            KdfAlgo::Yubtc,
        )
        .expect("TPrivKey::new")
    }

    fn source(nonce: u32, amounts: &[u64]) -> Source {
        Source {
            privkey: pk(nonce),
            unspent: amounts
                .iter()
                .enumerate()
                .map(|(i, a)| utxo(*a, i as u32))
                .collect(),
        }
    }

    // --- default_selection -----------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn default_selection_empty_sources_returns_empty_mask() {
        let mask = default_selection(&[], None);
        assert!(mask.is_empty());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn default_selection_drain_selects_all() {
        let sources = vec![source(0, &[100, 200]), source(1, &[300])];
        let mask = default_selection(&sources, None);
        assert_eq!(mask, vec![true, true]);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn default_selection_target_meets_then_stops() {
        // First source (200 sat) covers the 150 target; second source
        // (300 sat) must NOT be selected.
        let sources = vec![source(0, &[200]), source(1, &[300])];
        let mask = default_selection(&sources, Some(TSatoshi::new(150)));
        assert_eq!(mask, vec![true, false]);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn default_selection_walks_earliest_addresses_first() {
        // Earliest source has 50 sat — not enough; selection must
        // include the next address too.
        let sources = vec![source(0, &[50]), source(1, &[100])];
        let mask = default_selection(&sources, Some(TSatoshi::new(120)));
        assert_eq!(mask, vec![true, true]);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn default_selection_break_leaves_later_sources_unselected() {
        // The target is met at source 0, so sources 1-3 must stay
        // unselected even though they would overshoot further.
        let sources = vec![
            source(0, &[500]),
            source(1, &[600]),
            source(2, &[700]),
            source(3, &[800]),
        ];
        let mask = default_selection(&sources, Some(TSatoshi::new(450)));
        assert_eq!(mask, vec![true, false, false, false]);
    }

    // --- markers / address_for ----------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn markers_lists_nonce_vout_pairs_in_scan_order() {
        let sources = vec![source(0, &[100, 200, 300]), source(1, &[400])];
        let marks = markers(&sources);
        assert_eq!(
            marks,
            vec![
                (TNonce::new(0), 0),
                (TNonce::new(0), 1),
                (TNonce::new(0), 2),
                (TNonce::new(1), 0),
            ]
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn markers_empty_when_no_utxos() {
        let sources = vec![source(0, &[]), source(1, &[])];
        assert!(markers(&sources).is_empty());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn address_for_returns_address_of_matching_nonce() {
        let sources = vec![source(0, &[100]), source(1, &[200])];
        let marker: Marker = (TNonce::new(1), 0);
        let addr = address_for(&sources, marker).expect("nonce 1 exists");
        assert_eq!(addr, sources[1].privkey.get_address());
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn address_for_unknown_nonce_is_none() {
        let sources = vec![source(0, &[100])];
        let marker: Marker = (TNonce::new(9), 0);
        assert_eq!(address_for(&sources, marker), None);
    }

    // --- compute_total ----------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn compute_total_sums_utxos_of_selected_sources() {
        let sources = vec![source(0, &[100, 200]), source(1, &[400])];
        let mask = vec![true, false];
        assert_eq!(compute_total(&sources, &mask), 300);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn compute_total_with_all_selected() {
        let sources = vec![source(0, &[100]), source(1, &[200])];
        let mask = vec![true, true];
        assert_eq!(compute_total(&sources, &mask), 300);
    }

    // --- size / outputs ---------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn estimate_tx_size_is_overhead_plus_inputs_and_outputs() {
        let size = estimate_tx_size(2, 2);
        assert_eq!(size, 10 + 2 * 148 + 2 * 34);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn count_outputs_one_when_drain() {
        assert_eq!(count_outputs(1_000, None, TSatoshi::ZERO), 1);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn count_outputs_two_when_cashback_needed() {
        assert_eq!(
            count_outputs(1_000, Some(TSatoshi::new(500)), TSatoshi::new(100)),
            2
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn count_outputs_one_when_exact_match() {
        assert_eq!(
            count_outputs(600, Some(TSatoshi::new(500)), TSatoshi::new(100)),
            1
        );
    }

    // --- compute_fee_and_size --------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn fee_zero_runs_feekb_calculation() {
        // size for (1 in, 2 out) = 10 + 148 + 68 = 226.
        let (fee, size) = compute_fee_and_size(
            1,
            1_000,
            Some(TSatoshi::new(500)),
            TSatoshi::ZERO,
            TSatoshi::new(1000),
        );
        assert_eq!(fee, TSatoshi::new(226));
        assert_eq!(size, 226);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn fee_pinned_passes_through_unchanged() {
        let (fee, _) = compute_fee_and_size(
            1,
            1_000,
            Some(TSatoshi::new(500)),
            TSatoshi::new(1234),
            TSatoshi::new(1000),
        );
        assert_eq!(fee, TSatoshi::new(1234));
    }

    // --- materialise -------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn materialise_flattens_selected_sources() {
        let sources = vec![source(0, &[100, 200]), source(1, &[300])];
        let flat = materialise(&sources, &[true, false]);
        assert_eq!(flat.len(), 2);
        assert_eq!(flat[0].1.amount, 100);
        assert_eq!(flat[1].1.amount, 200);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn materialise_skips_unselected() {
        let sources = vec![source(0, &[100]), source(1, &[200])];
        let flat = materialise(&sources, &[false, true]);
        assert_eq!(flat.len(), 1);
        assert_eq!(flat[0].1.amount, 200);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn taddress_round_trip() {
        let addr = TAddress::new("1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
        assert_eq!(addr.to_string(), "1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
    }
}
