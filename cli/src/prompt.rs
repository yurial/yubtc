//! Seed / passphrase entry — testable primitives.
//!
//! This module holds the stdin-line helpers that are fully
//! unit-testable with in-memory readers ([`std::io::Cursor`]): seed
//! reading (whitespace-trimmed) and piped-passphrase reading
//! (only the trailing newline is stripped, inner/leading whitespace
//! preserved), plus the shared entry orchestration
//! ([`read_seed_and_passphrase_from`]): the passphrase is read
//! FIRST, then the seed — and an empty passphrase hides the seed
//! read as well (no echo, like a password read, so a bystander
//! cannot see the seed being typed).
//!
//! The terminal dispatch ([`read_seed_and_passphrase`]) lives in
//! `prompt_tty.rs` — the `rpassword` / TTY-detection branch cannot be
//! exercised without a real terminal, so that file is excluded from
//! coverage measurement by policy (`--ignore-filename-regex` in CI).
//! It is re-exported here so command modules can keep importing
//! `crate::prompt::read_seed_and_passphrase`.
//!
//! The seed/passphrase handling mirrors
//! `yubtc-python/src/yubtc/seed.py:get_seed_and_passphrase` except
//! for the prompt order (the passphrase comes first here) and the
//! hidden seed read on an empty passphrase: the seed is
//! whitespace-trimmed; the passphrase is read raw (whitespace
//! preserved) and treated as `""` when empty.
//!
//! Reception-time seed validation ([`validate_entered_seed`]) also
//! lives here: every command that accepts a seed from the user calls
//! it right after reading, before any KDF work. The policy is
//! permissive by default (any non-empty phrase, R-1); the opt-in
//! `--strict-bip39` flag (R-3) adds the full BIP-39 parse plus the
//! C6 entropy floor (R-4/R-5). In both modes a low entropy estimate
//! only prints a warning (R-6); the empty phrase always errors
//! (R-2).

use std::io::{self, BufRead, Write};

use yubtc_core::misc::{TPassphrase, TSeed};

use crate::error::CliError;

// Terminal-only dispatch (rpassword + is_terminal routing). File lives
// next to this one; excluded from coverage measurement by policy.
#[path = "prompt_tty.rs"]
mod prompt_tty;

pub use prompt_tty::{read_seed_and_passphrase, read_seed_and_passphrase_stderr};

/// Label [`prompt_seed`] writes before the seed read. A separate const
/// so tests can pin the exact prompt text without capturing stdout
/// (a piped shell `read` sees this exact byte string).
/// Map an `io::Error` from any stdin/stdout plumbing to
/// [`CliError::Stdin`].
///
/// A named function (not a closure) on purpose: closures inside
/// generic functions get one coverage entity per monomorphisation,
/// and the `StdinLock` ones can never execute their error path
/// headlessly. A single shared function is covered once by the
/// invalid-UTF-8 tests below.
pub(crate) fn stdin_err(e: io::Error) -> CliError {
    CliError::Stdin(e.to_string())
}

/// Label [`prompt_seed`] writes before the seed read. A separate const
/// so tests can pin the exact prompt text without capturing stdout
/// (a piped shell `read` sees this exact byte string).
pub(crate) const SEED_PROMPT: &str = "Seed: ";

/// Label the no-echo read prints before the passphrase (a terminal
/// sees this exact byte string from `rpassword`). A separate const so
/// tests can pin the exact prompt text.
pub(crate) const PASSPHRASE_PROMPT: &str = "Passphrase: ";

/// Print `Seed: ` to stdout (no newline) and flush, so a piped `read`
/// sees the prompt. Used when the user is expected to paste a seed
/// interactively.
///
/// Errors (mapped to [`CliError::Stdin`]) only when stdout cannot be
/// written or flushed (closed pipe / full disk).
pub fn prompt_seed() -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(SEED_PROMPT.as_bytes())
        .and_then(|_| stdout.flush())
        .map_err(stdin_err)
}

/// [`prompt_seed`] variant writing the label to **stderr**.
///
/// Used by the `psbt` subcommand group: those commands are
/// stdin→stdout filters whose stdout must stay machine-readable (a
/// base64 / hex / JSON payload line, specs/spec.md «PSBT — BIP-174»,
/// ОВ-6) — the human-facing prompt is a diagnostic and follows the
/// fee / warning lines to stderr.
pub fn prompt_seed_stderr() -> Result<(), CliError> {
    let mut stderr = io::stderr().lock();
    stderr
        .write_all(SEED_PROMPT.as_bytes())
        .and_then(|_| stderr.flush())
        .map_err(stdin_err)
}

/// Read the seed from stdin (one line) — used by `newseed` (which has
/// no passphrase) and any other seed-only entry point.
///
/// Blocks until one line (or EOF) arrives on real stdin; at EOF the
/// returned seed is the empty string. The line is whitespace-trimmed
/// before construction (BIP-39 phrases are whitespace-insensitive).
pub fn read_seed() -> Result<TSeed, CliError> {
    let stdin = io::stdin();
    let mut handle = stdin.lock();
    read_seed_from(&mut handle)
}

/// Validate a user-entered seed at reception under the selected
/// policy (specs/spec.md «Seed policy», R-1…R-6) — before any KDF work or
/// network access.
///
/// Contract: `seed` is the raw (already whitespace-trimmed) user
/// input; `strict_bip39` selects the reception policy — `false`
/// (the default, no flag) is permissive: any non-empty phrase is
/// accepted (R-1); `true` (`--strict-bip39`) additionally requires
/// the full BIP-39 parse (wordlist + checksum, 12/15/18/21/24 words)
/// and the C6 entropy floor (R-4/R-5). The empty phrase is rejected
/// in both modes (R-2). On success the non-blocking entropy-estimate
/// warning (R-6) is printed to stderr when the phrase's estimated
/// bits are below [`yubtc_core::seed::
/// MIN_ENTROPY_WARNING_BITS`]; execution continues regardless.
/// Returns `Err(CliError::Seed)` carrying the reason for any
/// rejection (empty phrase, parse error, or strict entropy-rule
/// violation). Never panics; performs no I/O besides the warning
/// line on stderr.
pub(crate) fn validate_entered_seed(seed: &TSeed, strict_bip39: bool) -> Result<(), CliError> {
    let policy = if strict_bip39 {
        yubtc_core::seed::SeedPolicy::StrictBip39
    } else {
        yubtc_core::seed::SeedPolicy::Permissive
    };
    yubtc_core::seed::validate_seed_with_policy(seed, policy)?;
    // R-6: the warning accompanies acceptance in both modes and
    // never blocks. Stderr keeps stdout machine-readable (the
    // address / WIF / tx lines).
    if let Some(warning) = yubtc_core::seed::entropy_warning(seed.as_str()) {
        eprintln!("warning: {warning}");
    }
    Ok(())
}

/// Read one line from `handle` and return it wrapped in [`TSeed`],
/// whitespace-trimmed.
///
/// Contract: `handle` is any readable UTF-8 line source. At EOF
/// returns the empty seed. Returns [`CliError::Stdin`] when the
/// underlying read fails (I/O error or invalid UTF-8).
///
/// Takes `dyn BufRead` (not a generic) on purpose: generic helpers
/// produce one coverage entity per monomorphisation, and the
/// `StdinLock` ones cannot be exercised headlessly.
pub(crate) fn read_seed_from(handle: &mut dyn BufRead) -> Result<TSeed, CliError> {
    Ok(TSeed::new(read_trimmed_line(handle)?))
}

/// Read one raw line from `handle`, trimmed with [`str::trim`]
/// (leading/trailing whitespace, `\n`, `\r` all removed).
///
/// Contract: at EOF returns `Ok("")`; I/O or UTF-8 failures return
/// [`CliError::Stdin`].
pub(crate) fn read_trimmed_line(handle: &mut dyn BufRead) -> Result<String, CliError> {
    let mut line = String::new();
    handle.read_line(&mut line).map_err(stdin_err)?;
    Ok(line.trim().to_string())
}

/// Read the passphrase as the second piped stdin line (the Python CLI
/// convention for non-TTY stdin).
///
/// Contract: only a single trailing `\n` or `\r\n` is stripped; every
/// other character — leading whitespace, inner spaces, unicode — is
/// preserved verbatim, because BIP-39 passphrases are byte-exact. At
/// EOF returns `Ok("")`. Returns [`CliError::Stdin`] when the
/// underlying read fails (I/O error or invalid UTF-8).
pub(crate) fn read_passphrase_line(handle: &mut dyn BufRead) -> Result<String, CliError> {
    let mut line = String::new();
    handle.read_line(&mut line).map_err(stdin_err)?;
    Ok(line
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string())
}

/// The no-echo reader injected by the terminal dispatch: print
/// `label` (no trailing newline) and read one secret line without
/// echo. On a real terminal this is `rpassword::prompt_password`;
/// tests substitute an in-memory fake.
pub(crate) type ReadHidden<'a> = &'a mut dyn FnMut(&str) -> io::Result<String>;

/// Read the passphrase FIRST, then the seed — the shared entry
/// orchestration behind [`read_seed_and_passphrase`], split out so
/// the prompt order and the hidden-input selection are unit-testable
/// with in-memory readers.
///
/// Contract: `handle` is the piped stdin source; `stdin_is_tty`
/// reports the terminal state; `read_hidden` performs the no-echo
/// reads (`rpassword` on a real terminal); `print_seed_label` writes
/// the [`SEED_PROMPT`] label right before an echoed seed read (to
/// stdout for the interactive commands, to stderr for the `psbt`/`ms`
/// stdin→stdout filters).
///
/// The passphrase is always read first: on a TTY via `read_hidden`
/// (no echo), on a pipe it is the first stdin line (raw bytes, only
/// the trailing newline stripped). The seed comes second: when the
/// passphrase is empty AND stdin is a TTY, the seed is read hidden as
/// well (a bystander must not see the seed being typed); a non-empty
/// passphrase keeps the plain echoed line read, and on a pipe there
/// is no echo, so the seed is the next stdin line either way — the
/// `Seed: ` label is printed before it. The seed is whitespace-trimmed
/// in both paths; the passphrase keeps its bytes verbatim. Returns
/// [`CliError::Stdin`] when any underlying read fails (I/O error or
/// invalid UTF-8) or when the label cannot be written.
pub(crate) fn read_seed_and_passphrase_from(
    handle: &mut dyn BufRead,
    stdin_is_tty: bool,
    read_hidden: ReadHidden<'_>,
    print_seed_label: &mut dyn FnMut() -> Result<(), CliError>,
) -> Result<(TSeed, TPassphrase), CliError> {
    // Passphrase first: TTY → no-echo read; pipe → first stdin line.
    let passphrase = TPassphrase::new(if stdin_is_tty {
        read_hidden(PASSPHRASE_PROMPT).map_err(stdin_err)?
    } else {
        read_passphrase_line(handle)?
    });

    // Seed second. An empty passphrase hides the seed too (like a
    // password read); a non-empty one keeps the echoed line read,
    // with the label printed so a piped shell `read` sees the prompt.
    let seed = if stdin_is_tty && passphrase.is_empty() {
        TSeed::new(
            read_hidden(SEED_PROMPT)
                .map_err(stdin_err)?
                .trim()
                .to_string(),
        )
    } else {
        print_seed_label()?;
        read_seed_from(handle)?
    };

    Ok((seed, passphrase))
}

#[cfg(test)]
mod tests {
    //! In-memory (Cursor) tests for the stdin-line primitives.
    #![allow(unexpected_cfgs)] // llvm-cov passes `--cfg coverage`; Cargo doesn't declare it

    use std::cell::{Cell, RefCell};
    use std::io::{self, Cursor};

    use crate::error::CliError;
    use yubtc_core::misc::TSeed;

    use super::{
        prompt_seed, read_passphrase_line, read_seed, read_seed_and_passphrase_from,
        read_seed_from, read_trimmed_line, validate_entered_seed, PASSPHRASE_PROMPT, SEED_PROMPT,
    };

    // --- read_trimmed_line -------------------------------------------

    #[test]
    fn trimmed_line_strips_surrounding_whitespace() {
        let mut cur = Cursor::new(b"  abandon ability  \n".to_vec());
        assert_eq!(
            read_trimmed_line(&mut cur).expect("read"),
            "abandon ability"
        );
    }

    #[test]
    fn trimmed_line_strips_crlf() {
        let mut cur = Cursor::new(b"seed\r\n".to_vec());
        assert_eq!(read_trimmed_line(&mut cur).expect("read"), "seed");
    }

    #[test]
    fn trimmed_line_at_eof_is_empty() {
        let mut cur = Cursor::new(Vec::new());
        assert_eq!(read_trimmed_line(&mut cur).expect("read"), "");
    }

    #[test]
    fn trimmed_line_invalid_utf8_is_stdin_error() {
        let mut cur = Cursor::new(b"\xff\xfe\n".to_vec());
        let err = read_trimmed_line(&mut cur).expect_err("invalid UTF-8 must error");
        assert!(err.to_string().starts_with("stdin: "), "{err}");
    }

    // --- read_seed_from ----------------------------------------------

    #[test]
    fn seed_from_trims_line_and_wraps_in_tseed() {
        let mut cur = Cursor::new(b"  zoo zoo zoo  \n".to_vec());
        let seed = read_seed_from(&mut cur).expect("read");
        assert_eq!(seed.as_str(), "zoo zoo zoo");
    }

    #[test]
    fn seed_from_at_eof_is_empty_seed() {
        let mut cur = Cursor::new(Vec::new());
        let seed = read_seed_from(&mut cur).expect("read");
        assert_eq!(seed.as_str(), "");
    }

    #[test]
    fn seed_from_invalid_utf8_propagates_stdin_error() {
        // Exercises read_seed_from's own `?` error arm (the inner
        // reader's error path is tested directly above).
        let mut cur = Cursor::new(b"\xff\xfe\n".to_vec());
        let err = read_seed_from(&mut cur).expect_err("invalid UTF-8 must error");
        assert!(err.to_string().starts_with("stdin: "), "{err}");
    }

    // --- read_passphrase_line ----------------------------------------

    #[test]
    fn passphrase_line_strips_lf() {
        let mut cur = Cursor::new(b"correct horse\n".to_vec());
        assert_eq!(
            read_passphrase_line(&mut cur).expect("read"),
            "correct horse"
        );
    }

    #[test]
    fn passphrase_line_strips_crlf() {
        let mut cur = Cursor::new(b"correct horse\r\n".to_vec());
        assert_eq!(
            read_passphrase_line(&mut cur).expect("read"),
            "correct horse"
        );
    }

    #[test]
    fn passphrase_line_preserves_leading_and_inner_whitespace() {
        let mut cur = Cursor::new(b"  two  words \n".to_vec());
        assert_eq!(
            read_passphrase_line(&mut cur).expect("read"),
            "  two  words "
        );
    }

    #[test]
    fn passphrase_line_without_trailing_newline_is_kept_verbatim() {
        let mut cur = Cursor::new(b"no newline".to_vec());
        assert_eq!(read_passphrase_line(&mut cur).expect("read"), "no newline");
    }

    #[test]
    fn passphrase_line_empty_line_is_empty_passphrase() {
        let mut cur = Cursor::new(b"\n".to_vec());
        assert_eq!(read_passphrase_line(&mut cur).expect("read"), "");
    }

    #[test]
    fn passphrase_line_invalid_utf8_is_stdin_error() {
        let mut cur = Cursor::new(b"\xff\n".to_vec());
        let err = read_passphrase_line(&mut cur).expect_err("invalid UTF-8 must error");
        assert!(err.to_string().starts_with("stdin: "), "{err}");
    }

    // --- read_seed_and_passphrase_from -------------------------------

    /// In-memory no-echo reader: records the labels it is called with
    /// and answers each call with the next line of `answers`
    /// (panicking past the end, which would mean an unexpected extra
    /// hidden read).
    fn fake_hidden<'a>(
        labels: &'a RefCell<Vec<String>>,
        answers: &'a [&'a str],
    ) -> impl FnMut(&str) -> io::Result<String> + 'a {
        let mut idx = 0;
        move |label: &str| {
            labels.borrow_mut().push(label.to_string());
            let answer = answers
                .get(idx)
                .expect("fake hidden reader consulted more times than scripted");
            idx += 1;
            Ok((*answer).to_string())
        }
    }

    /// Label-printer recording its call count in `count`.
    fn counting_label(count: &Cell<usize>) -> impl FnMut() -> Result<(), CliError> + '_ {
        move || {
            count.set(count.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn seed_prompt_label_is_stable() {
        // Pinned byte-for-byte: shell `read` prompts and the Python
        // CLI print the same label.
        assert_eq!(SEED_PROMPT, "Seed: ");
    }

    #[test]
    fn passphrase_prompt_label_is_stable() {
        // Pinned byte-for-byte: rpassword prints this on a TTY.
        assert_eq!(PASSPHRASE_PROMPT, "Passphrase: ");
    }

    #[test]
    fn entry_reads_passphrase_line_before_the_seed_line() {
        // Piped stdin: the FIRST line is the passphrase, the SECOND
        // the seed (the new prompt order). The `Seed: ` label is
        // printed before the echoed seed read; no no-echo read
        // happens on a pipe.
        let mut cur = Cursor::new(b"p1\ns1\n".to_vec());
        let labels = RefCell::new(Vec::new());
        let mut hidden = fake_hidden(&labels, &[]);
        let prints = Cell::new(0);
        let mut print_label = counting_label(&prints);

        let (seed, passphrase) =
            read_seed_and_passphrase_from(&mut cur, false, &mut hidden, &mut print_label)
                .expect("read");
        assert_eq!(passphrase.as_str(), "p1");
        assert_eq!(seed.as_str(), "s1");
        assert_eq!(prints.get(), 1, "the Seed: label precedes the seed read");
        assert!(labels.borrow().is_empty(), "no no-echo read on a pipe");
    }

    #[test]
    fn entry_piped_empty_passphrase_keeps_seed_on_stdin() {
        // Empty passphrase on a pipe: no echo concept exists there, so
        // the seed stays the next stdin line (line 1 empty, line 2 the
        // seed) — and the no-echo reader is never consulted.
        let mut cur = Cursor::new(b"\ns1\n".to_vec());
        let labels = RefCell::new(Vec::new());
        let mut hidden = fake_hidden(&labels, &[]);
        let prints = Cell::new(0);
        let mut print_label = counting_label(&prints);

        let (seed, passphrase) =
            read_seed_and_passphrase_from(&mut cur, false, &mut hidden, &mut print_label)
                .expect("read");
        assert_eq!(passphrase.as_str(), "");
        assert_eq!(seed.as_str(), "s1");
        assert_eq!(prints.get(), 1);
        assert!(labels.borrow().is_empty(), "no no-echo read on a pipe");
    }

    #[test]
    fn entry_tty_empty_passphrase_hides_the_seed_read() {
        // TTY + empty passphrase: the seed is read through the no-echo
        // reader (label order pins the prompt order: Passphrase:
        // first, Seed: second), the piped stdin line is never
        // consumed, and the echoed-read label is not printed.
        let mut cur = Cursor::new(b"echoed\n".to_vec());
        let labels = RefCell::new(Vec::new());
        let mut hidden = fake_hidden(&labels, &["", "zoo zoo zoo"]);
        let prints = Cell::new(0);
        let mut print_label = counting_label(&prints);

        let (seed, passphrase) =
            read_seed_and_passphrase_from(&mut cur, true, &mut hidden, &mut print_label)
                .expect("read");
        assert_eq!(passphrase.as_str(), "");
        assert_eq!(seed.as_str(), "zoo zoo zoo");
        assert_eq!(
            *labels.borrow(),
            vec![PASSPHRASE_PROMPT.to_string(), SEED_PROMPT.to_string()],
            "passphrase is prompted first, the hidden seed second"
        );
        assert_eq!(prints.get(), 0, "no echoed read → no Seed: label");
        assert_eq!(cur.position(), 0, "stdin is left untouched");
    }

    #[test]
    fn entry_tty_non_empty_passphrase_keeps_echoed_seed_read() {
        // TTY + non-empty passphrase: the passphrase is still the
        // no-echo read, but the seed keeps the plain echoed line read
        // (label printed, seed taken from stdin).
        let mut cur = Cursor::new(b"echoed seed\n".to_vec());
        let labels = RefCell::new(Vec::new());
        let mut hidden = fake_hidden(&labels, &["pw"]);
        let prints = Cell::new(0);
        let mut print_label = counting_label(&prints);

        let (seed, passphrase) =
            read_seed_and_passphrase_from(&mut cur, true, &mut hidden, &mut print_label)
                .expect("read");
        assert_eq!(passphrase.as_str(), "pw");
        assert_eq!(seed.as_str(), "echoed seed");
        assert_eq!(*labels.borrow(), vec![PASSPHRASE_PROMPT.to_string()]);
        assert_eq!(prints.get(), 1);
    }

    #[test]
    fn entry_hidden_seed_read_is_whitespace_trimmed() {
        // The hidden seed path trims like the echoed one (BIP-39
        // phrases are whitespace-insensitive; rpassword strips only
        // the trailing newline).
        let mut cur = Cursor::new(Vec::new());
        let labels = RefCell::new(Vec::new());
        let mut hidden = fake_hidden(&labels, &["", "  zoo zoo zoo  "]);
        let prints = Cell::new(0);
        let mut print_label = counting_label(&prints);

        let (seed, passphrase) =
            read_seed_and_passphrase_from(&mut cur, true, &mut hidden, &mut print_label)
                .expect("read");
        assert_eq!(passphrase.as_str(), "");
        assert_eq!(seed.as_str(), "zoo zoo zoo");
    }

    #[test]
    fn entry_tty_hidden_read_error_is_stdin_error() {
        // A failing no-echo read (rpassword plumbing) maps to
        // CliError::Stdin like every other stdin error.
        let mut cur = Cursor::new(Vec::new());
        let mut hidden = |_: &str| Err(io::Error::other("tty gone"));
        let prints = Cell::new(0);
        let mut print_label = counting_label(&prints);

        let err = read_seed_and_passphrase_from(&mut cur, true, &mut hidden, &mut print_label)
            .expect_err("no-echo read failure must error");
        assert!(err.to_string().starts_with("stdin: "), "{err}");
    }

    // --- prompt_seed ---------------------------------------------------

    #[test]
    fn prompt_seed_writes_label_and_flushes() {
        // Writes to the test-captured stdout; success is the contract.
        prompt_seed().expect("stdout write + flush");
    }

    // --- validate_entered_seed ----------------------------------------

    #[test]
    fn entered_seed_accepts_valid_bip39_phrase() {
        // BIP-39 test vector #2: 9 distinct words of 12 — passes
        // both the parse and the entropy floor in strict mode. The
        // estimate (~357 bits: 75 chars × log2(27)) is above the
        // warning threshold, so this call also exercises the silent
        // arm of the R-6 branch.
        let seed = TSeed::new(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        );
        validate_entered_seed(&seed, true).expect("valid high-entropy phrase accepted");
        validate_entered_seed(&seed, false).expect("permissive accepts the same phrase");
    }

    #[test]
    fn entered_seed_permissive_accepts_arbitrary_phrase() {
        // R-1: permissive (no flag) accepts any non-empty phrase —
        // no BIP-39 parse, no entropy floor. The estimate is below
        // 128 bits (~90 bits: 19 chars × log2(27)), so the
        // non-blocking warning arm fires too (R-6).
        let seed = TSeed::new("not a real mnemonic");
        validate_entered_seed(&seed, false).expect("permissive accepts non-BIP-39 input");
        // Strict still rejects the same phrase.
        let err = validate_entered_seed(&seed, true).expect_err("strict rejects garbage");
        assert!(matches!(err, CliError::Seed(_)), "got {err:?}");
        assert!(err.to_string().contains("parse error"), "{err}");
    }

    #[test]
    fn entered_seed_permissive_accepts_low_entropy_bip39_with_warning() {
        // Checksum-valid BIP-39 (vector #1), 2 distinct words of 12:
        // rejected under `--strict-bip39`, accepted permissively
        // (R-1). Its long text estimates ~442 bits, so no warning
        // fires — the R-6 estimate is formula-based, independent of
        // the C6 floor.
        let seed = TSeed::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        validate_entered_seed(&seed, false).expect("permissive accepts the low-entropy vector");
        let err = validate_entered_seed(&seed, true).expect_err("strict rejects");
        assert!(matches!(err, CliError::Seed(_)), "got {err:?}");
        assert!(err.to_string().contains("entropy too low"), "{err}");
        assert!(err.to_string().contains("distinct words"), "{err}");
    }

    #[test]
    fn entered_seed_permissive_silent_when_estimate_is_high() {
        // 28 lowercase chars ≈ 131.6 bits — accepted with NO warning
        // (the silent arm of the R-6 branch).
        let seed = TSeed::new("a".repeat(28));
        validate_entered_seed(&seed, false).expect("accepted");
    }

    #[test]
    fn entered_seed_rejects_garbage() {
        let seed = TSeed::new("not a real mnemonic");
        let err = validate_entered_seed(&seed, true).expect_err("garbage rejected");
        assert!(matches!(err, CliError::Seed(_)), "got {err:?}");
        assert!(err.to_string().contains("parse error"), "{err}");
    }

    #[test]
    fn entered_seed_rejects_empty_input() {
        // EOF on stdin yields the empty seed — rejected at reception
        // in both modes (R-2), before any backend resolution.
        let seed = TSeed::new("");
        for strict in [true, false] {
            let err = validate_entered_seed(&seed, strict)
                .expect_err("empty seed rejected in both modes");
            assert!(matches!(err, CliError::Seed(_)), "got {err:?}");
            assert!(err.to_string().contains("empty"), "strict={strict}: {err}");
        }
    }

    // --- read_seed (real stdin) ---------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn read_seed_reads_trimmed_line_from_real_stdin() {
        // Direct test of the stdin-backed entry point. Headless stdin
        // (CI, coverage, piped runs) is at EOF, so the seed is the
        // empty string; trimming itself is covered by the Cursor
        // tests above. The skip guard only exists for interactive
        // `cargo test` runs (a real terminal would block on the
        // read); llvm-cov builds pass `--cfg coverage`, compiling
        // the guard out so every line/branch here is measurable.
        // The trait method is called in trait-qualified form so the
        // `IsTerminal` import is not left unused in coverage builds.
        #[cfg(not(coverage))]
        if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            eprintln!("skipped: interactive stdin");
            return;
        }
        let seed = read_seed().expect("read_line on non-tty stdin");
        assert_eq!(seed.as_str(), "");
        // Drive the `StdinLock` instantiation of the pipe-passphrase
        // reader too: the only other caller is the terminal dispatch
        // in `prompt_tty.rs` (coverage-excluded), and the generic
        // instantiation is attributed to THIS file. EOF → "".
        let stdin = std::io::stdin();
        let mut handle = stdin.lock();
        assert_eq!(
            read_passphrase_line(&mut handle).expect("passphrase line"),
            ""
        );
    }
}
