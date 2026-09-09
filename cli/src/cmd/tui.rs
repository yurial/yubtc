//! Coin Control TUI for `send --interactive` — pure, headless-testable
//! parts.
//!
//! Ported from `yubtc-python/src/yubtc/tui.py`. The crossterm event
//! loop and terminal setup/teardown live in `tui_term.rs`, which is
//! excluded from coverage measurement by policy (it cannot run without
//! a real terminal); this module keeps everything else — the render
//! functions, the status line, the selection-mask helpers and the
//! headless-safe [`run_selection`] wrapper — at 100% coverage.
//!
//! # Wire format
//!
//! The TUI emits a `Vec<bool>` mask parallel to `sources`: `true` means
//! "use this source's UTXOs as inputs". [`run_selection`] is the
//! public entry point and returns:
//!
//! - `Some(mask)` — user pressed Enter.
//! - `None` — user pressed `q` or Esc.
//!
//! # Keys
//!
//! - `Space` / `Enter` — toggle / confirm.
//! - `a` — select all.
//! - `n` — clear selection.
//! - `j` / `k` / arrow down / arrow up — move cursor.
//! - `q` / Esc — cancel.

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

use yubtc_core::misc::{TAddress, TSatoshi};
use yubtc_core::wallet::Source;

use super::select::{materialise, SelectedUtxo};

// Terminal-only event loop + setup/teardown. File lives next to this
// one; excluded from coverage measurement by policy.
#[path = "tui_term.rs"]
mod tui_term;

/// Run the Coin Control TUI.
///
/// `sources` — `Vec<Source>` (one source per address) in scan order.
/// `target` — total satoshi the user wants to send (`None` = drain).
/// `fee` — hard-set fee (`0` means "compute from feekb").
/// `feekb` — fee rate in sat/kB.
/// `cashback_addr` — address for change (shown in the status line).
///
/// Contract: empty `sources` short-circuits to `Ok(None)` without
/// touching the terminal (headless-safe). Non-empty input enters the
/// terminal loop; without a controlling terminal (`/dev/tty`) the
/// setup fails and the `io::Error` is returned as-is.
pub fn run_selection(
    sources: Vec<Source>,
    target: Option<TSatoshi>,
    fee: TSatoshi,
    feekb: TSatoshi,
    cashback_addr: Option<TAddress>,
) -> std::io::Result<Option<Vec<bool>>> {
    if sources.is_empty() {
        return Ok(None);
    }
    tui_term::run_selection(sources, target, fee, feekb, cashback_addr)
}

fn selected_count(selected: &[bool]) -> usize {
    selected.iter().filter(|s| **s).count()
}

#[allow(clippy::too_many_arguments)]
fn render(
    frame: &mut ratatui::Frame,
    sources: &[Source],
    selected: &[bool],
    list_state: &mut ListState,
    total: u64,
    target: Option<TSatoshi>,
    fee: TSatoshi,
    size: usize,
    cashback_addr: Option<&TAddress>,
) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            // Three rows: top border + one status line + bottom
            // border. Two rows would leave zero interior rows once
            // the full borders are drawn and the status text would
            // never reach the screen.
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);

    let items: Vec<ListItem> = sources
        .iter()
        .enumerate()
        .map(|(i, source)| {
            let addr = source.privkey.get_address();
            let checked = if selected.get(i).copied().unwrap_or(false) {
                "[x]"
            } else {
                "[ ]"
            };
            let source_total: u64 = source.unspent.iter().map(|u| u.amount).sum();
            let line = Line::from(vec![
                Span::raw(format!("{} ", checked)),
                Span::styled(
                    format!("{}# ", source.privkey.nonce),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(addr.to_string()),
                Span::raw(format!(
                    " — {source_total} sat ({} UTXOs)",
                    source.unspent.len()
                )),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Coin Control (Space=toggle a=all n=none Enter=ok q=cancel)"),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_stateful_widget(list, chunks[0], list_state);

    let status = format_status(total, target, fee, size, cashback_addr);
    frame.render_widget(
        Paragraph::new(status).block(Block::default().borders(Borders::ALL).title("Status")),
        chunks[1],
    );

    let help = "[Space]=toggle [a]=all [n]=none [Enter]=ok [q]=cancel";
    frame.render_widget(Paragraph::new(help), chunks[2]);
}

fn format_status(
    total: u64,
    target: Option<TSatoshi>,
    fee: TSatoshi,
    size: usize,
    cashback_addr: Option<&TAddress>,
) -> String {
    let fee_sat = fee.get();
    let cashback_str = match cashback_addr {
        Some(addr) => format!(" cashbackaddr={addr}"),
        None => String::new(),
    };
    match target {
        None => format!("Selected: {total} sat (drain) fee={fee_sat} size={size}B{cashback_str}"),
        Some(t) => {
            let t_sat = t.get();
            let required = t_sat + fee_sat;
            let cashback = if total >= t_sat + fee_sat {
                total - t_sat - fee_sat
            } else {
                0
            };
            let m1 = if total >= t_sat { "✓" } else { "" };
            let m2 = if total >= required { "✓" } else { "" };
            format!(
                "{m1}Selected: {total}/{t_sat} {m2}Target: {t_sat}/{required} fee={fee_sat} size={size}B cashback={cashback}{cashback_str}"
            )
        }
    }
}

/// Convert a `Vec<bool>` mask into the flat list of `(TPrivKey, Utxo)`
/// pairs the wallet consumes.
///
/// Public so [`crate::cmd::send`] doesn't need to know the
/// `Vec<bool>` shape — it gets the flat shape the wallet's
/// `make_transaction` expects.
pub fn to_selected(sources: Vec<Source>, mask: Vec<bool>) -> Vec<SelectedUtxo> {
    materialise(&sources, &mask)
}

#[cfg(test)]
mod tests {
    //! Headless tests: TestBackend-driven render checks plus pure
    //! helper coverage for the Coin Control TUI.
    #![allow(unexpected_cfgs)] // llvm-cov passes `--cfg coverage`; Cargo doesn't declare it

    use ratatui::backend::TestBackend;
    use ratatui::widgets::ListState;
    use ratatui::Terminal;

    use yubtc_core::kdf::KdfAlgo;
    use yubtc_core::misc::{TNonce, TPassphrase, TSatoshi, TSeed};
    use yubtc_core::wallet::{Source, TPrivKey, Utxo};

    use super::{format_status, run_selection, selected_count, to_selected};

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
            &TSeed::new(format!("seed nonce={nonce}")),
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

    /// Render `sources` into a TestBackend (`args.width` x 15) and
    /// return the drawn buffer as newline-joined rows, so assertions
    /// read like the screen the user sees. 60 cols pins the real CLI
    /// layout; wider buffers are used when a full status line (with
    /// the 34-char cashback address) must not truncate.
    fn draw_to_text(args: RenderArgs) -> String {
        let mut terminal =
            Terminal::new(TestBackend::new(args.width, 15)).expect("TestBackend terminal");
        let mut list_state = ListState::default();
        if args.list_select < args.sources.len() {
            list_state.select(Some(args.list_select));
        }
        terminal
            .draw(|frame| {
                super::render(
                    frame,
                    &args.sources,
                    &args.selected,
                    &mut list_state,
                    args.total,
                    args.target,
                    args.fee,
                    args.size,
                    args.cashback_addr.as_ref(),
                );
            })
            .expect("draw");
        let buffer = terminal.backend().buffer();
        let width = buffer.area.width as usize;
        let mut text = String::new();
        for (i, cell) in buffer.content.iter().enumerate() {
            if i > 0 && i % width == 0 {
                text.push('\n');
            }
            text.push_str(cell.symbol());
        }
        text
    }

    struct RenderArgs {
        width: u16,
        sources: Vec<Source>,
        selected: Vec<bool>,
        list_select: usize,
        total: u64,
        target: Option<TSatoshi>,
        fee: TSatoshi,
        size: usize,
        cashback_addr: Option<yubtc_core::misc::TAddress>,
    }

    // --- selected_count ------------------------------------------------

    #[test]
    fn selected_count_counts_true_entries() {
        assert_eq!(selected_count(&[]), 0);
        assert_eq!(selected_count(&[true]), 1);
        assert_eq!(selected_count(&[true, false, true, true]), 3);
        assert_eq!(selected_count(&[false, false]), 0);
    }

    // --- format_status -------------------------------------------------

    #[test]
    fn status_drain_without_cashback() {
        assert_eq!(
            format_status(1_000, None, TSatoshi::new(100), 226, None),
            "Selected: 1000 sat (drain) fee=100 size=226B"
        );
    }

    #[test]
    fn status_drain_with_cashback() {
        let addr = yubtc_core::misc::TAddress::new("1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
        assert_eq!(
            format_status(1_000, None, TSatoshi::new(100), 226, Some(&addr)),
            "Selected: 1000 sat (drain) fee=100 size=226B \
             cashbackaddr=1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
        );
    }

    #[test]
    fn status_target_met_with_cashback_change() {
        // total >= target + fee → both ✓, cashback = total - target - fee.
        assert_eq!(
            format_status(
                1_000,
                Some(TSatoshi::new(500)),
                TSatoshi::new(100),
                226,
                None
            ),
            "✓Selected: 1000/500 ✓Target: 500/600 fee=100 size=226B cashback=400"
        );
    }

    #[test]
    fn status_target_exact_match_has_no_cashback() {
        // total == target + fee → both ✓, cashback = 0.
        assert_eq!(
            format_status(600, Some(TSatoshi::new(500)), TSatoshi::new(100), 226, None),
            "✓Selected: 600/500 ✓Target: 500/600 fee=100 size=226B cashback=0"
        );
    }

    #[test]
    fn status_target_partial_needs_fee() {
        // target <= total < target + fee → first ✓ only, cashback = 0.
        assert_eq!(
            format_status(550, Some(TSatoshi::new(500)), TSatoshi::new(100), 226, None),
            "✓Selected: 550/500 Target: 500/600 fee=100 size=226B cashback=0"
        );
    }

    #[test]
    fn status_target_unmet() {
        // total < target → no ✓ at all.
        assert_eq!(
            format_status(100, Some(TSatoshi::new(500)), TSatoshi::new(100), 226, None),
            "Selected: 100/500 Target: 500/600 fee=100 size=226B cashback=0"
        );
    }

    #[test]
    fn status_target_with_cashback_addr() {
        let addr = yubtc_core::misc::TAddress::new("1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
        assert_eq!(
            format_status(
                1_000,
                Some(TSatoshi::new(500)),
                TSatoshi::new(100),
                226,
                Some(&addr)
            ),
            "✓Selected: 1000/500 ✓Target: 500/600 fee=100 size=226B cashback=400 \
             cashbackaddr=1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
        );
    }

    // --- render (TestBackend) -------------------------------------------
    //
    // The Status block is `Length(3)` with full borders → exactly one
    // interior row, so the `format_status` text IS on screen; the
    // tests below pin that (the block used to be Length(2), which
    // left zero interior rows and hid the status line entirely).

    #[test]
    fn render_shows_title_rows_status_frame_and_help() {
        let sources = vec![source(0, &[100, 200]), source(1, &[300])];
        let addr0 = sources[0].privkey.get_address().to_string();
        let addr1 = sources[1].privkey.get_address().to_string();
        let text = draw_to_text(RenderArgs {
            width: 60,
            selected: vec![true, false],
            list_select: 0,
            total: 300,
            target: None,
            fee: TSatoshi::new(100),
            size: 226,
            cashback_addr: None,
            sources,
        });
        assert!(
            text.contains("Coin Control (Space=toggle a=all n=none Enter=ok"),
            "{text}"
        );
        assert!(text.contains(&format!("[x] 0# {addr0}")), "{text}");
        assert!(text.contains(&format!("[ ] 1# {addr1}")), "{text}");
        assert!(text.contains("Status"), "{text}");
        // The status line itself must be on screen (drain mode, no
        // target, no cashback): 60 cols fit the Selected/fee/size
        // prefix. Regression pin for the zero-interior-rows layout.
        assert!(text.contains("Selected: 300"), "{text}");
        assert!(text.contains("fee=100 size=226B"), "{text}");
        assert!(
            text.contains("[Space]=toggle [a]=all [n]=none [Enter]=ok [q]=cancel"),
            "{text}"
        );
    }

    #[test]
    fn render_target_mode_row_and_sums() {
        let sources = vec![source(0, &[600])];
        let addr0 = sources[0].privkey.get_address().to_string();
        let text = draw_to_text(RenderArgs {
            width: 120,
            selected: vec![true],
            list_select: 0,
            total: 600,
            target: Some(TSatoshi::new(500)),
            fee: TSatoshi::new(100),
            size: 226,
            cashback_addr: Some(yubtc_core::misc::TAddress::new(
                "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            )),
            sources,
        });
        // Full row incl. per-source total and UTXO count.
        assert!(
            text.contains(&format!("[x] 0# {addr0} — 600 sat (1 UTXOs)")),
            "{text}"
        );
        assert!(text.contains("Status"), "{text}");
        // Target mode with cashback address: the full status line
        // (120 cols) must be visible, not just the block frame.
        // total=600, target=500, fee=100 → required=600, cashback=0.
        assert!(
            text.contains(
                "✓Selected: 600/500 ✓Target: 500/600 fee=100 size=226B \
                 cashback=0 cashbackaddr=1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
            ),
            "{text}"
        );
    }

    #[test]
    fn render_short_mask_defaults_to_unchecked() {
        // A mask shorter than `sources` must render as unchecked, not
        // panic — `selected.get(i).copied().unwrap_or(false)`.
        let sources = vec![source(0, &[100]), source(1, &[200])];
        let text = draw_to_text(RenderArgs {
            width: 60,
            selected: vec![],
            list_select: 0,
            total: 0,
            target: Some(TSatoshi::new(50)),
            fee: TSatoshi::ZERO,
            size: 10,
            cashback_addr: None,
            sources,
        });
        assert!(text.contains("[ ] 0# "), "{text}");
        assert!(text.contains("[ ] 1# "), "{text}");
    }

    #[test]
    fn render_empty_sources_draws_frames_only() {
        let text = draw_to_text(RenderArgs {
            width: 60,
            sources: vec![],
            selected: vec![],
            list_select: 0,
            total: 0,
            target: None,
            fee: TSatoshi::ZERO,
            size: 0,
            cashback_addr: None,
        });
        assert!(
            text.contains("Coin Control (Space=toggle a=all n=none Enter=ok"),
            "{text}"
        );
        // No sources → no checkbox rows at all.
        assert!(!text.contains("[x]"), "{text}");
        assert!(!text.contains("[ ]"), "{text}");
    }

    // --- to_selected ----------------------------------------------------

    #[test]
    fn to_selected_flattens_mask_into_utxo_pairs() {
        let sources = vec![source(0, &[100, 200]), source(1, &[300])];
        let flat = to_selected(sources, vec![true, false]);
        assert_eq!(flat.len(), 2);
        assert_eq!(flat[0].0.nonce, TNonce::new(0));
        assert_eq!(flat[0].1.amount, 100);
        assert_eq!(flat[1].1.amount, 200);
    }

    #[test]
    fn to_selected_with_all_false_is_empty() {
        let sources = vec![source(0, &[100])];
        assert!(to_selected(sources, vec![false]).is_empty());
    }

    // --- run_selection headless contract --------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn run_selection_empty_sources_returns_none_without_terminal() {
        let result = run_selection(
            vec![],
            Some(TSatoshi::new(50)),
            TSatoshi::ZERO,
            TSatoshi::new(1000),
            None,
        );
        assert_eq!(
            result.expect("empty sources never touch the terminal"),
            None
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    // Unix-only: on Windows crossterm's raw mode succeeds even without
    // a controlling console and the event read blocks, so the "fails
    // fast" contract this test pins does not hold there. macOS and
    // Linux CI legs keep it; the coverage pipeline (Linux) compiles
    // the /dev/tty skip guard out via `--cfg coverage`.
    #[cfg(unix)]
    fn run_selection_without_controlling_terminal_returns_err() {
        // Covers the delegation into the terminal loop: without an
        // openable /dev/tty, crossterm's enable_raw_mode fails fast
        // and the io::Error propagates. The skip guard only exists
        // for interactive `cargo test` runs (the TUI would block on
        // the event read); llvm-cov builds pass `--cfg coverage`,
        // compiling the guard out so every line/branch here is
        // measurable.
        #[cfg(not(coverage))]
        if std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_ok()
        {
            eprintln!("skipped: controlling terminal present");
            return;
        }
        let result = run_selection(
            vec![source(0, &[100])],
            Some(TSatoshi::new(50)),
            TSatoshi::ZERO,
            TSatoshi::new(1000),
            None,
        );
        assert!(
            result.is_err(),
            "expected raw-mode failure without /dev/tty"
        );
    }
}
