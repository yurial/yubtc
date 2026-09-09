//! BIP-39 mnemonic seed phrases.
//!
//! Thin wrapper around the [`bip39`] crate (RustBIP39). The yubtc wallet
//! uses English wordlist, 12/15/18/21/24-word phrases — see
//! [`DEFAULT_SEED_WORDS`](crate::fwd::DEFAULT_SEED_WORDS) for the
//! default 15-word length.
//!
//! NFKD normalisation of the phrase is handled by [`bip39::Mnemonic::parse_in`].
//!
//! Reception of user-entered phrases is policy-based (specs/spec.md «Seed
//! policy», R-1…R-7): [`SeedPolicy::Permissive`] (the default) accepts
//! any non-empty phrase, [`SeedPolicy::StrictBip39`] adds the full
//! BIP-39 parse plus the C6 entropy floor. Both modes share the
//! non-blocking [`estimate_entropy`] / [`entropy_warning`] estimate.

use bip39::{Language, Mnemonic};

use crate::fwd::{DEFAULT_ALLOW_DUPS, DEFAULT_SEED_WORDS};
use crate::misc::TSeed;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SeedError {
    /// The phrase is empty (or whitespace-only after trim). A
    /// reception error in **both** policies (specs/spec.md «Seed policy»,
    /// R-2): nothing can be derived from an empty phrase.
    #[error("seed phrase is empty")]
    Empty,

    #[error("invalid word count {0}: must be 12, 15, 18, 21, or 24")]
    InvalidWordCount(usize),

    #[error("BIP-39 mnemonic parse error: {0}")]
    Parse(String),

    #[error("BIP-39 entropy error: {0}")]
    Entropy(String),

    #[error("entropy too low: {0}")]
    InsufficientEntropy(String),
}

/// Seed-reception policy (specs/spec.md «Seed policy», R-1…R-5;
/// DEVIATIONS.md D-001).
///
/// Determines which checks [`validate_seed_with_policy`] applies to a
/// user-entered phrase. Derivation is identical under both policies —
/// the KDF hashes the phrase as-is (R-7) — only reception differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedPolicy {
    /// Default (R-1): any non-empty phrase is accepted. The BIP-39
    /// parse (wordlist + checksum) and the C6 entropy floor are NOT
    /// applied; the R-6 entropy-estimate warning (see
    /// [`entropy_warning`]) still applies and is non-blocking.
    /// The only rejection is the empty phrase (R-2).
    Permissive,

    /// Opt-in strict BIP-39 (R-3/R-4): full BIP-39 parse (every word
    /// in the English wordlist, checksum valid, word count one of
    /// 12/15/18/21/24 — R-5) plus the C6 entropy floor (distinct-word
    /// minimum, [`MAX_WORD_REPEATS`] cap). Any violation is a
    /// blocking rejection before KDF. The empty phrase is rejected
    /// too (R-2). The R-6 warning still applies on success.
    StrictBip39,
}

/// Minimum distinct words required for a mnemonic of `words` length
/// (decision C6): `>= 4` of 12, `>= 5` of 15, `>= 6` of 18, `>= 7`
/// of 21, `>= 8` of 24 — i.e. `ceil(words / 3)`. Unsupported lengths
/// yield 0 (the word-count check is the gate for those).
pub fn min_unique_words(words: usize) -> usize {
    match words {
        12 => 4,
        15 => 5,
        18 => 6,
        21 => 7,
        24 => 8,
        _ => 0,
    }
}

/// Maximum times a single word may repeat in an accepted mnemonic
/// (decision C6). BIP-39 allows duplicates; a sequence where one word
/// occurs 3+ times is not a plausible random draw.
pub const MAX_WORD_REPEATS: usize = 2;

/// Entropy-floor validation over mnemonic words (decision C6,
/// specs/spec.md «Ключи и seed» → «Seed policy», entropy floor):
/// 1. distinct words >= `min_unique_words(words.len())`;
/// 2. no single word repeats more than [`MAX_WORD_REPEATS`] times
///    (this subsumes the "all words identical" obvious-pattern case).
///
/// Takes the word slice directly so the rules are testable without
/// hunting for a checksum-valid mnemonic with a rare word pattern.
/// Returns `SeedError::InsufficientEntropy` with a human-readable
/// rule violation.
pub fn validate_entropy<'a, I>(words: I) -> Result<(), SeedError>
where
    I: IntoIterator<Item = &'a str>,
{
    let words: Vec<&str> = words.into_iter().collect();
    let min = min_unique_words(words.len());
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for w in &words {
        *counts.entry(w).or_default() += 1;
    }
    let unique = counts.len();
    if unique < min {
        return Err(SeedError::InsufficientEntropy(format!(
            "only {unique} distinct words, need at least {min}"
        )));
    }
    let max_repeat = counts.values().max().copied().unwrap_or(0);
    if max_repeat > MAX_WORD_REPEATS {
        // Non-empty map invariant: a repeat count > 0 means at least
        // one entry exists, so the max-by-key lookup cannot fail.
        let (word, n) = counts
            .iter()
            .max_by_key(|(_, c)| **c)
            .expect("map is non-empty: some word exceeds the repeat cap");
        return Err(SeedError::InsufficientEntropy(format!(
            "word '{word}' repeats {n} times, max {MAX_WORD_REPEATS}"
        )));
    }
    Ok(())
}

/// Standard BIP-39 English-word mnemonic lengths. `usize` form so it
/// composes with [`crate::fwd::DEFAULT_SEED_WORDS`].
pub const SUPPORTED_WORD_COUNTS: &[usize] = &[12, 15, 18, 21, 24];

fn check_word_count(n: usize) -> Result<(), SeedError> {
    if SUPPORTED_WORD_COUNTS.contains(&n) {
        Ok(())
    } else {
        Err(SeedError::InvalidWordCount(n))
    }
}

/// Generate a fresh mnemonic with cryptographically secure entropy from
/// the OS RNG.
///
/// `words` must be one of `12 / 15 / 18 / 21 / 24` — anything else is
/// rejected with [`SeedError::InvalidWordCount`].
///
/// `unique` mirrors `yubtc-python/src/yubtc/seed.py:_generate_seed`:
/// `false` (the default, `DEFAULT_ALLOW_DUPS`) samples with
/// replacement — duplicate words are allowed and NEVER rejected;
/// `true` samples without replacement — the result is guaranteed
/// duplicate-free. Neither path errors on duplicates (the Python
/// reference cannot either: `choices` never checks and `sample`
/// cannot collide by construction). The bip39 crate always draws a
/// checksummed mnemonic, so `unique = true` regenerates until the
/// draw is duplicate-free instead: a 15-of-2048 draw is
/// duplicate-free with p ≈ 0.95, i.e. ~1.05 draws on average and
/// probability-0 of not terminating.
///
/// The only reachable error is `SeedError::InvalidWordCount`.
pub fn generate_seed(words: usize, unique: bool) -> Result<TSeed, SeedError> {
    check_word_count(words)?;
    // `generate_in` only fails for invalid word counts, which we've
    // already rejected above — so unwrap is safe here.
    let mut draw = || {
        Mnemonic::generate_in(Language::English, words)
            .expect("word count already validated by check_word_count")
    };
    let mnemonic = if unique {
        draw_until_unique(&mut draw, &has_duplicates)
    } else {
        // Decision C6: generated mnemonics must satisfy the same
        // entropy floor as imported ones (otherwise `newseed` could
        // emit a seed that `validate_seed` immediately rejects).
        // Redraws are extremely rare: a random 15-of-2048 draw has
        // >= 5 distinct words with p ≈ 1 - 1e-13. Reuses
        // `draw_until_unique` so the retry arm stays deterministically
        // testable with an injected draw.
        draw_until_unique(&mut draw, &|m| validate_entropy(m.words()).is_err())
    };
    Ok(TSeed(mnemonic.to_string()))
}

/// Redraw from `draw` until `is_duplicate` accepts the value — the
/// Rust equivalent of Python's `random.sample` (sampling without
/// replacement is not expressible with a checksummed mnemonic, so we
/// reject-and-redraw instead). Used with two predicates:
/// [`has_duplicates`] (the `unique = true` mode) and the C6 entropy
/// floor (the default mode).
///
/// Contract: `is_duplicate` decides for a freshly drawn value;
/// `draw` must be able to produce a passing value (with OS-RNG
/// entropy a 15-of-2048 draw is duplicate-free with p ≈ 0.95, so the
/// expected iteration count is ~1.05 and not terminating is
/// probability-0). Split out with an injected `draw` so the retry
/// arm is deterministically testable — an OS-RNG test cannot force a
/// duplicate first draw.
///
/// Both callables are taken as `dyn` (not generics) on purpose:
/// generic helpers produce one coverage entity per monomorphisation,
/// and the OS-RNG call sites can never execute the retry edge — a
/// single shared instantiation keeps the branch coverage honest (same
/// rationale as `read_seed_from` in the CLI).
fn draw_until_unique(
    draw: &mut dyn FnMut() -> Mnemonic,
    is_duplicate: &dyn Fn(&Mnemonic) -> bool,
) -> Mnemonic {
    let mut mnemonic = draw();
    while is_duplicate(&mnemonic) {
        mnemonic = draw();
    }
    mnemonic
}

fn has_duplicates(mnemonic: &Mnemonic) -> bool {
    let mut seen = std::collections::HashSet::new();
    mnemonic.words().any(|w| !seen.insert(w.to_owned()))
}

/// Entropy-estimate threshold for the non-blocking warning (specs/spec.md
/// «Seed policy», R-6; the constants table pins the value at 128).
/// A phrase whose character-class estimate falls below this many bits
/// triggers a warning in every reception mode; the warning never
/// blocks reception.
pub const MIN_ENTROPY_WARNING_BITS: u32 = 128;

/// Rough entropy estimate of an arbitrary phrase in bits (specs/spec.md
/// «Seed policy», R-6):
///
/// `bits = length * log2(|charset|)`
///
/// where `length` is the phrase length in chars (Unicode scalar
/// values, not bytes) and `|charset|` is the sum of the sizes of the
/// character classes **present** in the phrase:
///
/// | Class                       | Size |
/// |-----------------------------|------|
/// | lowercase (`a`–`z`)         | 26   |
/// | uppercase (`A`–`Z`)         | 26   |
/// | digits (`0`–`9`)            | 10   |
/// | space (`' '`)               | 1    |
/// | any other char (incl. non-ASCII and control chars) | 33 |
///
/// The estimate is intentionally crude — it is the basis of a
/// non-blocking warning ([`entropy_warning`]), never of a rejection.
///
/// Contract: `phrase` is any string (emptiness is the caller's
/// concern, see R-2). Returns `0.0` for the empty phrase (the
/// charset is undefined there; `log2(0)` would be `-inf`). For a
/// non-empty phrase the result is finite and `>= 0.0` (every char
/// falls into some class, so `|charset| >= 1`). Never panics; no
/// I/O; allocation-free apart from the single pass.
pub fn estimate_entropy(phrase: &str) -> f64 {
    let mut charset: u32 = 0;
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_space = false;
    let mut has_other = false;
    for ch in phrase.chars() {
        if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else if ch == ' ' {
            has_space = true;
        } else {
            has_other = true;
        }
    }
    charset += u32::from(has_lower) * 26;
    charset += u32::from(has_upper) * 26;
    charset += u32::from(has_digit) * 10;
    charset += u32::from(has_space);
    charset += u32::from(has_other) * 33;
    let len = phrase.chars().count();
    if len == 0 {
        return 0.0;
    }
    len as f64 * (charset as f64).log2()
}

/// Threshold comparison for [`entropy_warning`], split out so the
/// boundary (`bits` exactly at [`MIN_ENTROPY_WARNING_BITS`] → no
/// warning; the comparison is strict `<`) is unit-testable with an
/// exact value — a real phrase cannot hit 128.0 exactly because no
/// achievable charset size is a power of two.
///
/// Contract: returns `true` only when `bits < 128.0`. `NaN` compares
/// false (no warning), but [`estimate_entropy`] never produces `NaN`.
fn entropy_below_threshold(bits: f64) -> bool {
    bits < f64::from(MIN_ENTROPY_WARNING_BITS)
}

/// Non-blocking low-entropy warning for a user-entered phrase
/// (specs/spec.md «Seed policy», R-6). Active in **both** reception modes.
///
/// Contract: returns `Some(warning)` when the phrase is non-empty
/// (after trim) and its [`estimate_entropy`] is below
/// [`MIN_ENTROPY_WARNING_BITS`]; `None` when the phrase has enough
/// estimated entropy **or** is empty/whitespace-only — emptiness is
/// a rejection (R-2) handled by [`validate_seed_with_policy`], and
/// the warning deliberately does not double-report it. The returned
/// string is a single user-presentable line (no trailing newline);
/// callers print/prefix it as they see fit. Never panics; no I/O.
pub fn entropy_warning(phrase: &str) -> Option<String> {
    if phrase.trim().is_empty() {
        return None;
    }
    let bits = estimate_entropy(phrase);
    if entropy_below_threshold(bits) {
        Some(format!(
            "low entropy: estimated {bits:.1} bits < \
             {MIN_ENTROPY_WARNING_BITS} bits; consider a longer or \
             more varied phrase"
        ))
    } else {
        None
    }
}

/// Parse and validate a mnemonic phrase under a reception policy
/// (specs/spec.md «Seed policy», R-1…R-5).
///
/// Contract: `seed` is the raw user phrase (already
/// whitespace-trimmed by the entry points; trailing/leading
/// whitespace here is tolerated by the emptiness check but not
/// normalised). Behaviour by policy:
///
/// - Both policies first reject the empty/whitespace-only phrase
///   with [`SeedError::Empty`] (R-2).
/// - [`SeedPolicy::Permissive`] accepts any other phrase unchanged —
///   no BIP-39 parse, no entropy floor (R-1).
/// - [`SeedPolicy::StrictBip39`] requires a full BIP-39 parse (all
///   words from the English wordlist, checksum valid) plus the C6
///   entropy floor ([`validate_entropy`]); any violation returns the
///   corresponding [`SeedError`] (`Parse` / `InvalidWordCount` /
///   `InsufficientEntropy`) and the caller must not derive from the
///   phrase (R-4/R-5).
///
/// Never panics; performs no I/O. Derivation is NOT performed here —
/// passing a phrase under either policy never changes KDF output
/// (R-7).
pub fn validate_seed_with_policy(seed: &TSeed, policy: SeedPolicy) -> Result<(), SeedError> {
    if seed.as_str().trim().is_empty() {
        return Err(SeedError::Empty);
    }
    match policy {
        SeedPolicy::Permissive => Ok(()),
        SeedPolicy::StrictBip39 => {
            let mnemonic = Mnemonic::parse_in(Language::English, seed.as_str())
                .map_err(|e| SeedError::Parse(e.to_string()))?;
            // Decision C6: the entropy floor is part of strict
            // acceptance — a checksum-valid but low-entropy phrase is
            // rejected before any KDF work.
            validate_entropy(mnemonic.words())
        }
    }
}

/// Strict-policy validation shorthand: full BIP-39 parse (wordlist +
/// checksum) plus the C6 entropy floor. Equivalent to
/// [`validate_seed_with_policy`]`(&seed, `[`SeedPolicy::StrictBip39`]`)`
/// — the pre-C8 `validate_seed` contract, retained for the fuzz
/// targets and strict-path call sites.
///
/// Contract: see [`validate_seed_with_policy`]; the empty phrase
/// yields [`SeedError::Empty`], a phrase outside the wordlist or
/// with a bad checksum/word count yields [`SeedError::Parse`], a
/// checksum-valid but low-entropy phrase (e.g. the all-`abandon`
/// vector) yields [`SeedError::InsufficientEntropy`].
pub fn validate_seed(seed: &TSeed) -> Result<(), SeedError> {
    validate_seed_with_policy(seed, SeedPolicy::StrictBip39)
}

/// Convert a valid mnemonic to its raw entropy bytes (16/20/24/28/32
/// depending on word count). Useful for [`crate::kdf`] which works on
/// bytes rather than strings.
pub fn seed_to_entropy(seed: &TSeed) -> Result<Vec<u8>, SeedError> {
    let mnemonic = Mnemonic::parse_in(Language::English, &seed.0)
        .map_err(|e| SeedError::Parse(e.to_string()))?;
    Ok(mnemonic.to_entropy())
}

/// Construct a mnemonic from raw entropy bytes (for tests and imports).
pub fn entropy_to_seed(entropy: &[u8]) -> Result<TSeed, SeedError> {
    let mnemonic =
        Mnemonic::from_entropy(entropy).map_err(|e| SeedError::Entropy(e.to_string()))?;
    Ok(TSeed(mnemonic.to_string()))
}

/// Convenience: the default seed length from
/// [`crate::fwd::DEFAULT_SEED_WORDS`].
pub fn default_generate() -> Result<TSeed, SeedError> {
    generate_seed(DEFAULT_SEED_WORDS, DEFAULT_ALLOW_DUPS)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    // --- generate_seed ------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn generate_default_yields_15_words() {
        let s = default_generate().unwrap();
        assert_eq!(s.words().len(), DEFAULT_SEED_WORDS);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn generate_each_supported_length() {
        for n in SUPPORTED_WORD_COUNTS {
            let s = generate_seed(*n, true).unwrap();
            assert_eq!(s.words().len(), *n);
        }
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn generate_rejects_unsupported_word_count() {
        assert!(matches!(
            generate_seed(13, true),
            Err(SeedError::InvalidWordCount(13))
        ));
        assert!(matches!(
            generate_seed(0, true),
            Err(SeedError::InvalidWordCount(0))
        ));
        assert!(matches!(
            generate_seed(25, true),
            Err(SeedError::InvalidWordCount(25))
        ));
    }

    // --- validate_seed ------------------------------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn validate_accepts_known_mnemonic() {
        // BIP-39 official test vector #2 (TREZOR). Vector #1
        // (abandon ×11 + about) is checksum-valid but fails the C6
        // entropy floor (2 distinct of 12) — see
        // seed_entropy_rejects_all_duplicates below.
        let phrase = "legal winner thank year wave sausage worth \
                      useful legal winner thank yellow";
        let s = TSeed::new(phrase);
        validate_seed(&s).unwrap();
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn validate_rejects_unknown_word() {
        let s = TSeed::new(
            "abandon abandon abandon abandon abandon \
                             abandon abandon abandon abandon abandon \
                             abandon abandon abandon",
        );
        assert!(matches!(validate_seed(&s), Err(SeedError::Parse(_))));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn validate_rejects_bad_checksum() {
        // Last word changed → checksum fails.
        let s = TSeed::new(
            "abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon",
        );
        assert!(matches!(validate_seed(&s), Err(SeedError::Parse(_))));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn validate_rejects_wrong_word_count() {
        // 11 words — even before checksum, structure is wrong.
        let s = TSeed::new("abandon ".repeat(11).trim().to_string());
        assert!(matches!(validate_seed(&s), Err(SeedError::Parse(_))));
    }

    // --- seed_to_entropy / entropy_to_seed ---------------------------

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn entropy_round_trip() {
        let original = default_generate().unwrap();
        let bytes = seed_to_entropy(&original).unwrap();
        // 15-word mnemonic → 160 bits → 20 bytes.
        assert_eq!(bytes.len(), 20);
        let restored = entropy_to_seed(&bytes).unwrap();
        assert_eq!(original, restored);
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn known_entropy_decodes() {
        // BIP-39 official test vector #1 entropy =
        // 00000000000000000000000000000000 (16 bytes → 12-word mnemonic).
        let bytes = [0u8; 16];
        let s = entropy_to_seed(&bytes).unwrap();
        assert_eq!(
            s.as_str(),
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about"
        );
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn entropy_to_seed_rejects_wrong_length() {
        // 15 bytes is not a valid BIP-39 entropy size (16/20/24/28/32).
        assert!(matches!(
            entropy_to_seed(&[0u8; 15]),
            Err(SeedError::Entropy(_))
        ));
        assert!(matches!(
            entropy_to_seed(&[0u8; 33]),
            Err(SeedError::Entropy(_))
        ));
    }

    #[ntest_timeout::timeout(5000)]
    #[test]
    fn seed_to_entropy_rejects_invalid_seed() {
        // Invalid seed → Mnemonic::parse_in fails → Parse error.
        assert!(matches!(
            seed_to_entropy(&TSeed::new("not a valid mnemonic at all".to_string())),
            Err(SeedError::Parse(_))
        ));
    }

    // --- entropy floor (decision C6) -----------------------------------

    /// `min_unique_words` floor for every supported length plus the
    /// unsupported pass-through (0 → the word-count check gates those).
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn min_unique_words_table() {
        assert_eq!(min_unique_words(12), 4);
        assert_eq!(min_unique_words(15), 5);
        assert_eq!(min_unique_words(18), 6);
        assert_eq!(min_unique_words(21), 7);
        assert_eq!(min_unique_words(24), 8);
        // Unsupported lengths: 0 (the word-count check rejects them
        // before the entropy floor is consulted).
        assert_eq!(min_unique_words(0), 0);
        assert_eq!(min_unique_words(11), 0);
        assert_eq!(min_unique_words(13), 0);
        assert_eq!(min_unique_words(25), 0);
    }

    /// Empty word list: no counts, no maximum → vacuously accepted
    /// (the floor only ever sees non-empty word lists from
    /// `validate_seed`, but the contract must not depend on that).
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn seed_entropy_accepts_empty_word_list() {
        let words: Vec<&str> = Vec::new();
        validate_entropy(words).expect("vacuously accepted");
    }

    /// Standard BIP-39 vector, all 12 words distinct — accepted.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn seed_entropy_accepts_valid_bip39_12_words() {
        let s = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let words: Vec<&str> = s.split_whitespace().collect();
        validate_entropy(words.iter().copied()).expect("8 distinct words of 12: accepted");
        validate_seed(&TSeed::new(s)).expect("full validate_seed accepts");
    }

    /// The classic all-"abandon" BIP-39 vector is checksum-valid but
    /// has 2 distinct words of 12 — rejected by the entropy floor.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn seed_entropy_rejects_all_duplicates() {
        let s = TSeed::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about",
        );
        // Sanity: the phrase IS valid BIP-39 (would pass checksum).
        Mnemonic::parse_in(Language::English, s.as_str()).expect("valid BIP-39");
        let err = validate_seed(&s).expect_err("entropy floor rejects");
        assert!(
            matches!(err, SeedError::InsufficientEntropy(_)),
            "got {err:?}"
        );
        assert!(err.to_string().contains("distinct words"), "got {err:?}");
    }

    /// 11 x "abandon" + 1 x "legal"-like variant: still below the
    /// distinct-word floor (3 distinct of 12 < 4).
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn seed_entropy_rejects_mostly_duplicates() {
        // 10 x abandon + zebra + zoo = 3 distinct < 4.
        let s = TSeed::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon zebra zoo",
        );
        let words: Vec<&str> = s.as_str().split_whitespace().collect();
        let err = validate_entropy(words.iter().copied()).expect_err("3 distinct < 4");
        assert!(err.to_string().contains("distinct words"), "got {err:?}");
    }

    /// "legal winner" x6: 2 distinct words, and each word repeats 6
    /// times (> MAX_WORD_REPEATS) — the repeats rule fires with its
    /// own message.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn seed_entropy_rejects_repeated_phrase() {
        // 12 words alternating two words: 2 distinct of 12 < 4 — the
        // distinct-word rule fires first (the repeats rule would too).
        let words = [
            "legal", "winner", "legal", "winner", "legal", "winner", "legal", "winner", "legal",
            "winner", "legal", "winner",
        ];
        let err = validate_entropy(words.iter().copied()).expect_err("2 distinct words rejected");
        assert!(err.to_string().contains("distinct words"), "got {err:?}");
    }

    /// The repeats cap: a mnemonic with >= 4 distinct words but one
    /// word present more than MAX_WORD_REPEATS times.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn seed_entropy_rejects_excessive_single_word_repeats() {
        // 12 words, 4 distinct, one word present 9 times (> 2).
        let words = [
            "abandon", "zebra", "zoo", "legal", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon",
        ];
        let err = validate_entropy(words.iter().copied()).expect_err("excessive repeat rejected");
        assert!(err.to_string().contains("repeats"), "got {err:?}");
    }

    /// generate_seed applies the same floor: every default draw must
    /// pass validate_seed end-to-end.
    #[ntest_timeout::timeout(30_000)]
    #[test]
    fn generated_seeds_pass_entropy_validation() {
        for _ in 0..200 {
            let s = generate_seed(15, false).expect("word count 15 is supported");
            validate_seed(&s).expect("generated seed passes the entropy floor");
        }
    }

    // --- unique guard -------------------------------------------------
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn has_duplicates_helper_detects_collision() {
        // BIP-39 test vector #1: 16 zero bytes →
        // "abandon abandon ... about" (12 words, 11× "abandon").
        let dup = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert!(has_duplicates(&dup));

        // Counter-example: the sha256-chain scan below finds a
        // duplicate-free 12-word mnemonic deterministically (each
        // 12-of-2048 draw has ~97% duplicate-free probability).
        let mut material = [0u8; 32];
        let clean = loop {
            let candidate = Mnemonic::from_entropy(&material[..16]).unwrap();
            if !has_duplicates(&candidate) {
                break candidate;
            }
            use sha2::Digest as _;
            material = sha2::Sha256::digest(material).into();
        };
        assert!(!has_duplicates(&clean));
    }

    /// Python-parity regression pin: the default (`unique = false`,
    /// `DEFAULT_ALLOW_DUPS`) must never reject a draw — duplicates
    /// are allowed. The previously inverted guard failed ~5% of
    /// 15-word draws (birthday bound), which this loop catches with
    /// overwhelming probability (0.95^1000 ≈ 5e-23 of passing a
    /// regression). All 1000 draws must succeed.
    #[ntest_timeout::timeout(30_000)]
    #[test]
    fn generate_seed_allows_duplicates_by_default() {
        for _ in 0..1000 {
            generate_seed(15, false).expect("default draw never rejects duplicates");
        }
    }

    /// `unique = true` guarantees a duplicate-free phrase (Python:
    /// `random.sample` without replacement). Each iteration forces
    /// the retry loop's decision at least once with p ≈ 5%; 25
    /// iterations leave a <1e-64 chance of never entering the loop
    /// body — the assertion on the OUTPUT is what matters and is
    /// checked every iteration.
    /// The retry arm, deterministically: the injected draw produces a
    /// duplicate mnemonic first (all-zero entropy), then a clean one
    /// — `draw_until_unique` must return the SECOND draw. An OS-RNG
    /// test cannot force this (duplicate first draws are ~5%).
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn draw_until_unique_retries_on_duplicate_first_draw() {
        let dup = Mnemonic::from_entropy(&[0u8; 16]).unwrap(); // all-"abandon"
        let clean = {
            let mut material = [1u8; 32];
            loop {
                let candidate = Mnemonic::from_entropy(&material[..16]).unwrap();
                if !has_duplicates(&candidate) {
                    break candidate;
                }
                use sha2::Digest as _;
                material = sha2::Sha256::digest(material).into();
            }
        };
        let mut calls = 0;
        let out = draw_until_unique(
            &mut || {
                calls += 1;
                if calls == 1 {
                    dup.clone()
                } else {
                    clean.clone()
                }
            },
            &has_duplicates,
        );
        assert_eq!(calls, 2, "exactly one retry");
        assert_eq!(out.to_string(), clean.to_string());
    }

    /// The entropy-floor redraw arm, deterministically: the injected
    /// draw produces the checksum-valid but low-entropy all-abandon
    /// mnemonic first (rejected by the C6 floor), then a clean one —
    /// the default (`unique = false`) path must return the SECOND
    /// draw. An OS-RNG test cannot force this (a failing first draw
    /// is probability ~1e-13).
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn default_draw_retries_on_entropy_floor_violation() {
        let low = Mnemonic::from_entropy(&[0u8; 16]).unwrap(); // 11× abandon + about
        let clean = {
            // Scan from the all-zero entropy: the first candidate IS
            // the low-entropy mnemonic, so the retry body executes at
            // least once; the sha256 chain then finds a clean draw at
            // a fixed iteration (deterministic, no flap).
            let mut material = [0u8; 32];
            loop {
                let candidate = Mnemonic::from_entropy(&material[..16]).unwrap();
                if validate_entropy(candidate.words()).is_ok() {
                    break candidate;
                }
                use sha2::Digest as _;
                material = sha2::Sha256::digest(material).into();
            }
        };
        validate_entropy(clean.words()).expect("clean draw passes the floor");
        let mut calls = 0;
        let out = draw_until_unique(
            &mut || {
                calls += 1;
                if calls == 1 {
                    low.clone()
                } else {
                    clean.clone()
                }
            },
            &|m| validate_entropy(m.words()).is_err(),
        );
        assert_eq!(calls, 2, "exactly one entropy redraw");
        assert_eq!(out.to_string(), clean.to_string());
    }

    #[ntest_timeout::timeout(30_000)]
    #[test]
    fn generate_seed_unique_yields_duplicate_free_phrase() {
        for _ in 0..25 {
            let seed = generate_seed(15, true).expect("word count 15 is supported");
            let mnemonic = Mnemonic::parse_in(Language::English, seed.as_str()).unwrap();
            assert!(!has_duplicates(&mnemonic));
        }
    }

    // --- seed policy (C8, specs/spec.md «Seed policy» R-1…R-7) ---------------

    /// R-1: permissive accepts an arbitrary non-BIP-39 phrase — no
    /// parse, no entropy floor.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn test_seed_permissive_accepts_arbitrary_phrase() {
        let s = TSeed::new("not a real mnemonic");
        validate_seed_with_policy(&s, SeedPolicy::Permissive)
            .expect("permissive accepts any non-empty phrase");
        // The same phrase is rejected by the strict shorthand.
        assert!(validate_seed(&s).is_err());
        // The checksum-valid but low-entropy vector is accepted too:
        // the C6 floor is strict-only (D-001).
        let low = TSeed::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about",
        );
        validate_seed_with_policy(&low, SeedPolicy::Permissive)
            .expect("entropy floor is not applied in permissive mode");
    }

    /// R-2: the empty (and whitespace-only) phrase is rejected in
    /// both modes.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn test_seed_permissive_rejects_empty() {
        for phrase in ["", "   ", "\t\n"] {
            let s = TSeed::new(phrase);
            for policy in [SeedPolicy::Permissive, SeedPolicy::StrictBip39] {
                let err = validate_seed_with_policy(&s, policy)
                    .expect_err("empty phrase rejected in both modes");
                assert_eq!(
                    err,
                    SeedError::Empty,
                    "policy {policy:?}, phrase {phrase:?}"
                );
            }
        }
    }

    /// R-5: a wrong word count in strict mode is an ordinary parse
    /// error (not a separate rejection kind).
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn test_seed_strict_rejects_wrong_word_count() {
        let s = TSeed::new("abandon ".repeat(13).trim());
        let err = validate_seed_with_policy(&s, SeedPolicy::StrictBip39)
            .expect_err("13 words are outside the BIP-39 lengths");
        assert!(matches!(err, SeedError::Parse(_)), "got {err:?}");
    }

    /// Strict-mode happy path and both strict failure classes flow
    /// through the policy entry point unchanged.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn test_seed_strict_policy_matches_shorthand() {
        let good = TSeed::new(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        );
        validate_seed_with_policy(&good, SeedPolicy::StrictBip39)
            .expect("valid vector accepted in strict mode");
        // Strict = the validate_seed shorthand.
        assert_eq!(
            validate_seed_with_policy(&good, SeedPolicy::StrictBip39),
            validate_seed(&good)
        );
        let garbage = TSeed::new("zzz qqq xxx");
        assert!(matches!(
            validate_seed_with_policy(&garbage, SeedPolicy::StrictBip39),
            Err(SeedError::Parse(_))
        ));
    }

    // --- entropy estimate (R-6) -----------------------------------------

    /// Single-class phrases pin the class table: each class
    /// contributes its size to the charset and is skipped when
    /// absent.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn estimate_entropy_single_class_phrases() {
        let log2 = |n: f64| n.log2();
        // Empty: defined 0.0 (documented contract).
        assert_eq!(estimate_entropy(""), 0.0);
        // Space-only: charset {space} = 1 → 0 bits (log2(1) = 0).
        assert_eq!(estimate_entropy(" "), 0.0);
        assert_eq!(estimate_entropy("   "), 0.0);
        // One lowercase char: 1 * log2(26).
        assert!((estimate_entropy("a") - log2(26.0)).abs() < 1e-12);
        // One uppercase char: 1 * log2(26).
        assert!((estimate_entropy("A") - log2(26.0)).abs() < 1e-12);
        // One digit: 1 * log2(10).
        assert!((estimate_entropy("7") - log2(10.0)).abs() < 1e-12);
        // One punctuation char («other» class): 1 * log2(33).
        assert!((estimate_entropy("!") - log2(33.0)).abs() < 1e-12);
        // Non-ASCII chars count as the «other» class too.
        assert!((estimate_entropy("é") - log2(33.0)).abs() < 1e-12);
    }

    /// Classes accumulate: a phrase with one char of every class has
    /// the full 96-char charset; length multiplies linearly.
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn estimate_entropy_accumulates_classes_and_length() {
        // a A 1 space ! → charset 26+26+10+1+33 = 96, length 5.
        let bits = estimate_entropy("aA1 !");
        assert!((bits - 5.0 * 96.0f64.log2()).abs() < 1e-9, "got {bits}");
        // Length is linear: twice the length, twice the bits.
        let doubled = estimate_entropy("aA1 !aA1 !");
        assert!((doubled - 2.0 * bits).abs() < 1e-9);
        // Adding a second char of an existing class does not grow
        // the charset: "aa" = 2 * log2(26), not 2 * log2(52).
        let two_lower = estimate_entropy("aa");
        assert!((two_lower - 2.0 * 26.0f64.log2()).abs() < 1e-12);
    }

    /// Critical points of the R-6 threshold: just below 128 bits →
    /// warning; 128 bits and above → silent. The exact-128 boundary
    /// itself is pinned on `entropy_below_threshold` (a real phrase
    /// cannot land exactly on 128.0 — no achievable charset size is
    /// a power of two).
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn entropy_below_threshold_boundary() {
        assert!(entropy_below_threshold(127.999));
        assert!(!entropy_below_threshold(128.0));
        assert!(!entropy_below_threshold(128.001));
        assert!(!entropy_below_threshold(f64::INFINITY));
    }

    /// bits < 128 → `Some(warning)` with the numbers in the text
    /// (R-6: the warning accompanies acceptance, never blocks).
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn test_seed_entropy_estimate_warns_below_128_bits() {
        // "abandon about": 13 chars, lowercase + space (27) →
        // ≈ 61.8 bits — far below the threshold.
        let phrase = "abandon about";
        let bits = estimate_entropy(phrase);
        assert!(bits < 128.0, "fixture must estimate below 128: {bits}");
        let warning = entropy_warning(phrase).expect("warning below the threshold");
        assert!(warning.contains("low entropy"), "{warning}");
        assert!(warning.contains("128"), "{warning}");
        // A short lowercase phrase: 27 chars → ≈126.9 bits, just
        // under the line.
        let just_under = "a".repeat(27);
        assert!(entropy_warning(&just_under).is_some());
    }

    /// bits >= 128 → no warning (R-6 upper side).
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn test_seed_entropy_estimate_silent_at_or_above_128_bits() {
        // 28 lowercase chars → ≈131.6 bits, just over the line.
        let just_over = "a".repeat(28);
        assert!(entropy_warning(&just_over).is_none());
        // Mixed classes reach the threshold much sooner: 15 chars of
        // the full 96-char charset ≈ 98.8 bits — still warns; 30
        // such chars ≈ 197.5 bits — silent.
        let mixed = "aA1 !aA1 !aA1 !";
        assert!(estimate_entropy(mixed) < 128.0);
        assert!(entropy_warning(mixed).is_some());
        let mixed_long = format!("{mixed}{mixed}");
        assert!(estimate_entropy(&mixed_long) >= 128.0);
        assert!(entropy_warning(&mixed_long).is_none());
    }

    /// The warning is silent for empty/whitespace-only input (R-2
    /// owns that rejection; the warning must not double-report it).
    #[ntest_timeout::timeout(5000)]
    #[test]
    fn entropy_warning_silent_for_empty_input() {
        assert!(entropy_warning("").is_none());
        assert!(entropy_warning("   ").is_none());
    }

    // --- proptest -----------------------------------------------------

    use proptest::prelude::*;

    /// BIP-39 entropy sizes: 128, 160, 192, 224, 256 bits → 16, 20,
    /// 24, 28, 32 bytes. Other sizes are rejected by the BIP-39 spec.
    fn entropy_size() -> impl proptest::strategy::Strategy<Value = Vec<u8>> {
        let sizes: [usize; 5] = [16, 20, 24, 28, 32];
        (0usize..sizes.len()).prop_map(move |i| {
            let n = sizes[i];
            (0..n as u8).collect()
        })
    }

    proptest! {
        #[ntest_timeout::timeout(5000)]
    #[test]
        fn entropy_round_trip_arbitrary(bytes in entropy_size()) {
            let seed = entropy_to_seed(&bytes).unwrap();
            let back = seed_to_entropy(&seed).unwrap();
            prop_assert_eq!(back, bytes);
        }
    }
}
