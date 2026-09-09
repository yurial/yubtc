//! Terminal-only Coin Control TUI plumbing — crossterm event loop.
//!
//! COVERAGE-EXCLUDED FILE: raw mode, the alternate screen and
//! `crossterm::event::read()` all require a real controlling terminal
//! and cannot be exercised headlessly. CI excludes this file from
//! llvm-cov measurement via `--ignore-filename-regex
//! '(^|/)(prompt_tty|tui_term)\.rs$'`; all decision logic (rendering,
//! status line, selection maths) lives in [`super`] (`tui.rs`) and is
//! unit-tested there with a `TestBackend`. Keep this file minimal —
//! pure code goes to `tui.rs`.

use std::io::{stdout, Stdout};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::widgets::ListState;
use ratatui::Terminal;

use yubtc_core::misc::{TAddress, TSatoshi};
use yubtc_core::wallet::Source;

use crate::cmd::select::{compute_fee_and_size, compute_total, default_selection};

use super::{render, selected_count};

/// Terminal entry point. Callers must guarantee `sources` is
/// non-empty (the headless wrapper in [`super::run_selection`]
/// short-circuits empty input before touching the terminal).
pub(super) fn run_selection(
    sources: Vec<Source>,
    target: Option<TSatoshi>,
    fee: TSatoshi,
    feekb: TSatoshi,
    cashback_addr: Option<TAddress>,
) -> std::io::Result<Option<Vec<bool>>> {
    let mut terminal = setup_terminal()?;
    let result = loop_tui(&mut terminal, sources, target, fee, feekb, cashback_addr);
    teardown_terminal(&mut terminal)?;
    Ok(result)
}

fn setup_terminal() -> std::io::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    Terminal::new(backend)
}

fn teardown_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> std::io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn loop_tui(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    sources: Vec<Source>,
    target: Option<TSatoshi>,
    fee: TSatoshi,
    feekb: TSatoshi,
    cashback_addr: Option<TAddress>,
) -> Option<Vec<bool>> {
    let mut selected = default_selection(&sources, target);
    let mut total = compute_total(&sources, &selected);
    let mut list_state = ListState::default();
    if !sources.is_empty() {
        list_state.select(Some(0));
    }

    loop {
        let (cur_fee, cur_size) =
            compute_fee_and_size(selected_count(&selected), total, target, fee, feekb);
        terminal
            .draw(|frame| {
                render(
                    frame,
                    &sources,
                    &selected,
                    &mut list_state,
                    total,
                    target,
                    cur_fee,
                    cur_size,
                    cashback_addr.as_ref(),
                );
            })
            .expect("ratatui draw");

        let event = crossterm::event::read().expect("crossterm read");
        if let Event::Key(KeyEvent {
            code,
            kind: KeyEventKind::Press,
            modifiers,
            ..
        }) = event
        {
            match code {
                KeyCode::Char('q') | KeyCode::Esc => return None,
                KeyCode::Enter => return Some(selected),
                KeyCode::Char(' ') => {
                    if let Some(i) = list_state.selected() {
                        if i < selected.len() {
                            selected[i] = !selected[i];
                            total = compute_total(&sources, &selected);
                        }
                    }
                }
                KeyCode::Char('a') => {
                    for s in selected.iter_mut() {
                        *s = true;
                    }
                    total = compute_total(&sources, &selected);
                }
                KeyCode::Char('n') => {
                    for s in selected.iter_mut() {
                        *s = false;
                    }
                    total = compute_total(&sources, &selected);
                }
                KeyCode::Down | KeyCode::Char('j') if !sources.is_empty() => {
                    let i = list_state.selected().unwrap_or(0);
                    let next = (i + 1).min(sources.len() - 1);
                    list_state.select(Some(next));
                }
                KeyCode::Up | KeyCode::Char('k') if !sources.is_empty() => {
                    let i = list_state.selected().unwrap_or(0);
                    let next = i.saturating_sub(1);
                    list_state.select(Some(next));
                }
                KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                    return None;
                }
                _ => {}
            }
        }
    }
}
