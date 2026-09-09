//! Cross-compat harness (Phase 1.5): read JSON-encoded KAT vectors from
//! stdin, run each through the corresponding Rust primitive, verify the
//! result matches the expected one.
//!
//! The Python side (`tests/test_xcompat.py` in the sibling
//! `yubtc-python-harness` repo) generates the JSON, pipes it in via
//! subprocess, and asserts the exit code is zero. Any silent divergence
//! between Rust and Python breaks the harness here.
//!
//! ## Wire format
//!
//! One JSON object per line on stdin. The `type` field selects the
//! primitive under test; `seed2bin` is the default for backwards
//! compatibility with vectors written before the field existed.
//!
//! ### `seed2bin` — verify `seed2bin` output bit-for-bit
//!
//! ```json
//! {"seed": "<mnemonic>", "nonce": 0, "passphrase": "", "kdf": "yubtc", "expected": "<hex>"}
//! ```
//!
//! `expected` is the 32-byte `seed2bin` output encoded as hex.
//!
//! ### `verify_sig` — verify a DER signature against a 32-byte digest
//!
//! ```json
//! {"type": "verify_sig", "seed": "<mnemonic>", "nonce": 0, "passphrase": "",
//!  "kdf": "yubtc", "datahash": "<32-byte hex>", "signature": "<DER hex>"}
//! ```
//!
//! The harness derives the privkey/pubkey from `(seed, nonce, passphrase,
//! kdf)` via `seed2privkey_with_kdf` and `privkey_to_pubkey`, then
//! verifies that the DER-encoded `signature` is valid for the
//! 32-byte `datahash` under that pubkey.
//!
//! `datahash` is the digest the Python side actually signed over:
//!
//! - For `sign_hash(privkey, datahash)` callers, it is the raw
//!   32-byte input passed to `sign_hash`.
//! - For `sign_data(privkey, data)` callers (Bitcoin transaction
//!   signing), it is `sha256(sha256(data))` — the caller computes
//!   it upstream so the harness stays oblivious to which function
//!   produced the signature.
//!
//! This split lets the same wire format exercise both primitives,
//! and lets a buggy `sign_hash` (e.g. one that internally hashes
//! its input before signing) surface here as a verification failure:
//! the signature would be over `sha256(datahash)` rather than
//! `datahash`, and the harness verifies against `datahash`.
//!
//! ## Exit codes
//!
//! - 0: every vector matched.
//! - 1: at least one vector failed (a divergence was found). The
//!   failing line number, the expected bytes, and the actual bytes
//!   are printed to stderr so the operator can diff.

use std::io::{self, BufRead, Write};
use std::process::ExitCode;

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;

use yubtc_core::kdf::{seed2bin, KdfAlgo};
use yubtc_core::misc::{TNonce, TPassphrase, TSeed};
use yubtc_core::privkey::{privkey_to_pubkey, seed2privkey_with_kdf};

/// The vector primitive the line exercises. `Seed2Bin` is the default
/// for lines written before the `type` field existed; serde fills it in
/// when the field is missing so existing KAT rows keep working.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum VectorType {
    #[default]
    Seed2Bin,
    VerifySig,
}

/// A line from stdin. `expected` is only populated by `seed2bin`
/// vectors; `datahash` / `signature` only by `verify_sig` vectors.
/// serde rejects lines where the wrong field is populated for the
/// declared type, so a vector with `expected` set but `type =
/// verify_sig` fails JSON deserialisation.
#[derive(Debug, Deserialize)]
struct Vector {
    #[serde(default)]
    #[serde(rename = "type")]
    kind: VectorType,
    seed: String,
    nonce: u32,
    passphrase: String,
    kdf: String,
    #[serde(default)]
    expected: String,
    #[serde(default)]
    datahash: String,
    #[serde(default)]
    signature: String,
}

fn parse_kdf(s: &str) -> Result<KdfAlgo, String> {
    match s {
        "yubtc" => Ok(KdfAlgo::Yubtc),
        "pbkdf2" => Ok(KdfAlgo::Pbkdf2),
        "argon2id" => Ok(KdfAlgo::Argon2id),
        "scrypt" => Ok(KdfAlgo::Scrypt),
        other => Err(format!("unknown kdf: {other}")),
    }
}

fn main() -> ExitCode {
    let stdin = io::stdin();
    let mut had_failure = false;
    let mut count = 0usize;

    for (idx, line) in stdin.lock().lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[kat_check] read error on line {}: {e}", idx + 1);
                had_failure = true;
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        count += 1;
        let v: Vector = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "[kat_check] JSON parse error on line {}: {e}\n  raw: {trimmed}",
                    idx + 1
                );
                had_failure = true;
                continue;
            }
        };
        let kdf = match parse_kdf(&v.kdf) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[kat_check] line {}: {e}", idx + 1);
                had_failure = true;
                continue;
            }
        };
        let seed = TSeed::new(v.seed);
        let nonce = TNonce::new(v.nonce);
        let pass = TPassphrase::new(v.passphrase);
        match v.kind {
            VectorType::Seed2Bin => {
                let expected_bytes = match hex::decode(&v.expected) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("[kat_check] line {}: bad expected hex: {e}", idx + 1);
                        had_failure = true;
                        continue;
                    }
                };
                if expected_bytes.len() != 32 {
                    eprintln!(
                        "[kat_check] line {}: expected must be 32 bytes, got {}",
                        idx + 1,
                        expected_bytes.len()
                    );
                    had_failure = true;
                    continue;
                }
                match seed2bin(&seed, nonce, &pass, kdf) {
                    Ok(actual) => {
                        let actual_hex = hex::encode(actual);
                        if actual_hex == v.expected {
                            // Verbose per-line PASS is suppressed; the harness
                            // prints only failures plus a one-line summary.
                        } else {
                            eprintln!(
                                "[kat_check] line {}: MISMATCH kdf={} nonce={}\n  expected: {}\n  actual:   {}",
                                idx + 1,
                                v.kdf,
                                v.nonce,
                                v.expected,
                                actual_hex
                            );
                            had_failure = true;
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[kat_check] line {}: seed2bin failed: {e} (expected hex: {})",
                            idx + 1,
                            v.expected
                        );
                        had_failure = true;
                    }
                }
            }
            VectorType::VerifySig => {
                let datahash = match hex::decode(&v.datahash) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("[kat_check] line {}: bad datahash hex: {e}", idx + 1);
                        had_failure = true;
                        continue;
                    }
                };
                if datahash.len() != 32 {
                    eprintln!(
                        "[kat_check] line {}: datahash must be 32 bytes, got {}",
                        idx + 1,
                        datahash.len()
                    );
                    had_failure = true;
                    continue;
                }
                let der_bytes = match hex::decode(&v.signature) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("[kat_check] line {}: bad signature hex: {e}", idx + 1);
                        had_failure = true;
                        continue;
                    }
                };
                let sig = match Signature::from_der(&der_bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!(
                            "[kat_check] line {}: signature is not valid DER: {e}",
                            idx + 1
                        );
                        had_failure = true;
                        continue;
                    }
                };
                let mut datahash_arr = [0u8; 32];
                datahash_arr.copy_from_slice(&datahash);
                let privkey = match seed2privkey_with_kdf(&seed, nonce, &pass, kdf) {
                    Ok(pk) => pk,
                    Err(e) => {
                        eprintln!("[kat_check] line {}: seed2privkey failed: {e}", idx + 1);
                        had_failure = true;
                        continue;
                    }
                };
                let pubkey_bytes = privkey_to_pubkey(&privkey);
                let vk = match VerifyingKey::from_sec1_bytes(&pubkey_bytes) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!(
                            "[kat_check] line {}: derived pubkey is not valid SEC1: {e}",
                            idx + 1
                        );
                        had_failure = true;
                        continue;
                    }
                };
                match vk.verify_prehash(&datahash_arr, &sig) {
                    Ok(()) => {
                        // Verified; per-line PASS is suppressed, only the
                        // summary line is printed on success.
                    }
                    Err(e) => {
                        eprintln!(
                            "[kat_check] line {}: SIGNATURE INVALID kdf={} nonce={}: {e}\n  datahash: {}\n  signature: {}",
                            idx + 1,
                            v.kdf,
                            v.nonce,
                            v.datahash,
                            v.signature
                        );
                        had_failure = true;
                    }
                }
            }
        }
    }

    let mut out = io::stdout().lock();
    if had_failure {
        let _ = writeln!(out, "[kat_check] FAIL: at least one vector diverged");
        ExitCode::FAILURE
    } else {
        let _ = writeln!(out, "[kat_check] OK: {count} vectors verified");
        ExitCode::SUCCESS
    }
}
