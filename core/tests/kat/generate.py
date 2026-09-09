#!/usr/bin/env python3
"""Generate fixed KAT vectors for the Rust core
(KAT policy — specs/spec.md «Качество и CI»).

Two axes, one file each:

**Address axis** -> `vectors.json` (default, `--axis address`). Pins
the Rust implementation (`core/src/kdf.rs`, `core/src/privkey.rs`,
`core/src/address.rs`, `core/src/wallet.rs`) bit-for-bit against known
answers. Each row carries the full pipeline: `seed2bin` -> privkey ->
addresses -> WIF.

Vector provenance (important):

Every row -- all four KDFs -- is computed by the `yubtc-python`
reference (`yubtc.crypto.seed2bin` / `seed2privkey` / `privkey2addr` /
`privkey2privwif` / `pubkey2segwit_addr` / `pubkey2taproot_addr`), the
bit-for-bit oracle. Since the KDF backport (reference commit e3f6cd3)
the reference implements `seed2bin(seed, nonce, passphrase, kdf=...)`
for all four algorithms ('yubtc', 'pbkdf2', 'argon2id', 'scrypt'), so
this generator carries no stretch code of its own; the frozen KDF
parameters recorded in the output are read from the reference module,
not duplicated here.

Phase 13 stage 3 adds the `addr_type` axis: every row carries an
`address_forms` dict with all three receive-address forms.

- `yubtc` / `argon2id` / `scrypt` (вариант A, spec ОВ-2): the same
  key as the pre-existing row fields, three *encodings* -- legacy
  P2PKH, native P2WPKH, taproot P2TR (BIP-86 TapTweak). The per-form
  `privkey`/`wif` are byte-identical to the row's.
- `pbkdf2` (BIP-39-compatible): each form is a *distinct key* --
  `seed2privkey(..., addr_type=...)` walks the purpose-specific
  BIP-32 leaf (`m/44'…` / `m/84'…` / `m/86'…`).

The segwit-capable reference lives on the `issue-segwit` branch of
`yubtc-python` (the KDF backport e3f6cd3 landed on master, SegWit did
not); `reference_commit` in the output records that branch's HEAD.

**PSBT axis** -> `psbt_vectors.json` (`--axis psbt`, Phase 14 stage 3).
For the same 16 (seed, passphrase, KDF, nonce)-tuples each row replays
the full BIP-174 pipeline `create -> sign -> finalize -> extract`
through the `yubtc.psbt` mirror (the bit-for-bit oracle of
`core/src/psbt.rs`) and records the four stage strings: the unsigned /
signed / finalized base64 containers plus the extracted wire
transaction hex. Every row is the *three-forms* fixture: one legacy
P2PKH input (with `NON_WITNESS_UTXO`), one P2WPKH and one P2TR input
(each with `WITNESS_UTXO`), all keyed at the row's nonce -- so the
Signer nonce walk, all three `SigScheme`s and all three Finalizer
layouts are exercised on every tuple. The file additionally carries
one *unknown-fields* variant (three opaque pairs injected into the
global/input/output maps before the pipeline) and one *combine* pair
(`a` = signed container; `combined` = merge with a synthetic
disjoint-signer `PARTIAL_SIG` and one extra unknown global pair) --
the row design of the mirror's `tests/test_psbt.py::RUST_ROWS`,
derived end-to-end from the reference instead of pinned constants.

**Multi-sig axis** -> `ms_vectors.json` (`--axis ms`, Phase 15
stage 3/4). For the mirror's multi-sig fixture family (two seeds,
cascade KDF, empty passphrase) each row is a `(N, M, keys, nonce)`
tuple: the own legacy-form key at `own_nonce` plus the cosigner keys
at the row's `key_nonces`, all derived from the row seed -- passed to
`yubtc.wallet.ms_create_address` in the row's rotated order (R-MS-4:
unsorted input, canonical output) and pinned as `address` /
`redeem_hex` / `script_pubkey_hex`. Every row also replays the
2-of-3 five-stage PSBT pipeline through the mirror's P2SH-multisig
branches (`ms_fixture_psbt` design of `tests/test_multisig.py`): the
prev tx pays 60_000 sat to the quorum address, the spend goes to the
row seed's native-P2WPKH key at nonce 9 for 50_000 sat, and the
stages `unsigned -> signed_a (own key) -> combined (first cosigner)
-> signed_ab/combined -> finalized -> wire_hex` (+ display `txid`,
`scriptsig_len`) are recorded. The anchor row
(`phase15multisig`, own_nonce 0) equals the mirror's
`tests/test_multisig.py::MS_ROWS` parity rows bit-for-bit; its wire
carries the 253-byte multisig `scriptSig` -- the D-002 CompactSize
pin (`fd fd 00` at bytes 41..44, the first yubtc script past the
LEB128 divergence point).

v0.3 adds two witness-form arrays of the SAME 16 tuples:

- **P2WSH** (`witness_vectors`): `bc1q...` v0/32 `SHA256(redeem)`
  commitment, byte-identical redeem script, BIP-143 Signer over the
  witness script, the BIP-141 stack `[empty dummy, M sigs, redeem]`
  (`witness_items = M + 2 = 4`).
- **P2TR script-path** (`tapscript_vectors`): the R-MS-7 CHECKSIGADD
  tapscript over the x-only key projections (a *different* script
  than the p2sh/p2wsh redeem), the `bc1p...` v1 commitment to the
  tweaked NUMS output key, the BIP-341 script-path Signer (untweaked
  BIP-340, SIGHASH_DEFAULT) and the R-MS-11 Finalizer stack
  `[N reversed sig slots, tapscript, 33-byte control block]`
  (`witness_items = N + 2 = 5`, `final_scriptwitness_len = 271`).
  Each row pins the crypto chain (`leaf_hash` / `output_key` /
  `control` / own `sighash` + `own_sig`) and mirrors the Python
  parity fixture `tests/fixtures/tapscript_ms_rows.json` row for
  row.

Usage::

    python3 core/tests/kat/generate.py
        [--axis address|psbt|ms|all] [--python-src DIR]

Writes the selected JSON files next to this script. Fully
deterministic; safe to re-run. The reference repo is only read, never
modified. The reference is located via `--python-src`, the canonical
checkouts, an already-importable `yubtc` package (e.g.
`pip install -e`), or side-by-side checkouts next to this repo / the
current directory (the PSBT axis additionally requires `psbt.py`).
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[2]  # core/tests/kat -> core -> repo root

# Segwit-capable reference checkout (branch issue-segwit; the master
# backport e3f6cd3 predates SegWit).
REFERENCE_SRC = Path('/home/iu.diachenko/wt/yubtc-python/issue-segwit/src')

# PSBT-mirror reference checkout (branch issue-psbt; carries the
# `yubtc.psbt` BIP-174 mirror plus everything the address axis needs).
PSBT_REFERENCE_SRC = Path('/home/iu.diachenko/wt/yubtc-python/issue-psbt/src')

# Multi-sig mirror reference checkout (branch issue-multisig; carries
# the Phase 15 P2SH-multisig mirror: `wallet.ms_*`, the PSBT
# P2SH-multisig branches and the D-002 CompactSize transaction fix).
MS_REFERENCE_SRC = Path('/home/iu.diachenko/wt/yubtc-python/issue-multisig/src')

# Tapscript-mirror reference checkout (branch issue-tapscript-ms; the
# v0.3 P2WSH + P2TR script-path mirror -- a superset of the multisig
# one, so the whole ms axis regenerates from it; canonical source of
# the parity fixture `tapscript_ms_rows.json`).
TAPSCRIPT_REFERENCE_SRC = Path(
    '/home/iu.diachenko/wt/yubtc-python/issue-tapscript-ms/src')

# --- Matrix -------------------------------------------------------------

# One valid 12-word BIP-39 mnemonic + one arbitrary non-BIP-39 phrase
# (the default seed policy is permissive). ASCII only: the legacy
# cascade latin-1-encodes the seed.
SEEDS = [
    'abandon abandon abandon abandon abandon abandon '
    'abandon abandon abandon abandon abandon about',
    'yubtc kat vector seed not a bip39 phrase 12345',
]

# Empty passphrase (yubtc only) vs non-empty passphrase (the rest).
# "hunter2" keeps the rows cross-checkable against the hex values
# pinned in yubtc-python/tests/test_xcompat.py KAT_ROWS.
PASSPHRASE_EMPTY = ''
PASSPHRASE_NON_EMPTY = 'hunter2'

NONCES = [0, 7]
KDFS = ['yubtc', 'pbkdf2', 'argon2id', 'scrypt']

# The receive-address forms every row carries (Phase 13, spec ОВ-2).
ADDR_TYPES = ['legacy', 'native', 'taproot']


def address_forms(seed: str, nonce: int, passphrase: str, kdf: str,
                  row_privkey) -> dict:
    """Derive the three address forms for one KAT row.

    `row_privkey` is the row's own key (the legacy form for every
    KDF). For `pbkdf2` the native/taproot forms re-derive their
    purpose-specific keys; for the other KDFs (вариант A) all three
    forms encode the same key.
    """
    from yubtc import crypto

    forms = {}
    for addr_type in ADDR_TYPES:
        if kdf == 'pbkdf2':
            key = crypto.seed2privkey(seed=seed, nonce=nonce,
                                      passphrase=passphrase, kdf=kdf,
                                      addr_type=addr_type)
        else:
            key = row_privkey
        pubkey = crypto.privkey2pubkey(privkey=key)
        if addr_type == 'legacy':
            address = crypto.privkey2addr(privkey=key).decode('ascii')
        elif addr_type == 'native':
            address = crypto.pubkey2segwit_addr(pubkey=pubkey)
        else:
            address = crypto.pubkey2taproot_addr(pubkey=pubkey)
        forms[addr_type] = {
            'addr_type': addr_type,
            'privkey': key.secret.hex(),
            'address': address,
            'wif': crypto.privkey2privwif(privkey=key).decode('ascii'),
        }
    # Variant-A KDFs: same key, three encodings; pbkdf2: the legacy
    # form must be the row's own key (default purpose 44).
    for addr_type in ADDR_TYPES:
        if kdf != 'pbkdf2' or addr_type == 'legacy':
            assert forms[addr_type]['privkey'] == row_privkey.secret.hex()
    return forms


def derive(seed: str, nonce: int, passphrase: str, kdf: str) -> dict:
    """Derive one KAT row: seed2bin -> privkey -> addresses -> wif."""
    from yubtc import crypto

    # All four KDFs go through the reference; the kdf kwarg selects the
    # algorithm. seed2privkey applies the X25519-style clamp to the
    # cascade branch only (decision C1). The default addr_type is the
    # legacy form, matching the pre-existing row fields.
    raw = crypto.seed2bin(seed=seed, nonce=nonce, passphrase=passphrase,
                          kdf=kdf)
    privkey = crypto.seed2privkey(seed=seed, nonce=nonce,
                                  passphrase=passphrase, kdf=kdf)

    return {
        'seed': seed,
        'nonce': nonce,
        'passphrase': passphrase,
        'kdf': kdf,
        'seed2bin': raw.hex(),
        'privkey': privkey.secret.hex(),
        'address': crypto.privkey2addr(privkey=privkey).decode('ascii'),
        'wif': crypto.privkey2privwif(privkey=privkey).decode('ascii'),
        'address_forms': address_forms(seed, nonce, passphrase, kdf,
                                       privkey),
        'provenance': 'yubtc-python reference',
    }


def build_vectors() -> list:
    rows = []
    for kdf in KDFS:
        passphrase = PASSPHRASE_EMPTY if kdf == 'yubtc' else PASSPHRASE_NON_EMPTY
        for nonce in NONCES:
            for seed in SEEDS:
                rows.append(derive(seed, nonce, passphrase, kdf))
    return rows


# --- PSBT axis (Phase 14, stage 3) ---------------------------------------

# The row design constants, ported bit-for-bit from the mirror's
# `tests/test_psbt.py` (the `RUST_ROWS` production recipe): a fixed
# prev-tx skeleton, RBF-signaled sequences and the synthetic
# disjoint-signer injection for the combine pair. The fixture *keys*
# are not constants -- every stage is derived from the reference for
# the row's own (seed, passphrase, kdf, nonce) tuple.
PSBT_RBF = 0xfffffffe

PSBT_COMBINE_SYNTHETIC_PUBKEY = b'\x02' * 33
PSBT_COMBINE_SYNTHETIC_SIG = b'\xbb' * 64
PSBT_COMBINE_SYNTHETIC_UNKNOWN = (b'\x51\x07', b'\x09')

# The opaque pairs injected into the three maps of the unknown-fields
# variant (one per map: global / input 1 / output 0).
PSBT_UNKNOWN_INJECTIONS = (
    ('global', b'\x51\xaa\xbb', b'\x01\x02\x03'),
    ('input', b'\x52\xcc', b'\x04\x05'),
    ('output', b'\x53\xdd\xee', b'\x06'),
)


def _psbt_spk(crypto, fwd, hash_, script, seed: str, nonce: int,
              passphrase: str, kdf: str, form: str) -> bytes:
    """`scriptPubKey` of the `(nonce, form)` key under
    `(seed, passphrase, kdf)` -- the mirror's `spk` helper."""
    key = crypto.seed2privkey(seed=seed, nonce=nonce, passphrase=passphrase,
                              kdf=kdf, addr_type=form)
    pubkey = crypto.privkey2pubkey(privkey=key)
    if form == fwd.AddrType.LEGACY:
        return bytes(script.CScript([script.OP_DUP, script.OP_HASH160,
                                     hash_.hash160(pubkey),
                                     script.OP_EQUALVERIFY,
                                     script.OP_CHECKSIG]))
    if form == fwd.AddrType.NATIVE:
        return bytes(script.make_p2wpkh_lock_script(
            hash160=hash_.hash160(pubkey)))
    return bytes(script.make_p2tr_lock_script(
        output_key=crypto.taproot_output_key(internal_xonly=pubkey[1:33])))


def _three_forms_psbt(mods, seed: str, nonce: int, passphrase: str,
                      kdf: str):
    """The three-forms fixture of one tuple: a prev tx paying the
    legacy/native/taproot forms of `nonce`, an unsigned tx spending all
    three UTXOs (legacy with its full prev-tx for `NON_WITNESS_UTXO`),
    one native change output -- built via `create_psbt`."""
    crypto, psbt, fwd, hash_, script = mods
    spk = lambda n, form: _psbt_spk(crypto, fwd, hash_, script, seed, n,
                                    passphrase, kdf, form)
    prev = psbt.PsbtTransaction(
        version=2,
        vin=(psbt.PsbtTxIn(txhash=b'\x11' * 32, n=3, script=b'',
                           sequence=PSBT_RBF, witness=()),),
        vout=(psbt.PsbtTxOut(amount=60_000, script=spk(nonce, fwd.AddrType.LEGACY)),
              psbt.PsbtTxOut(amount=30_000, script=spk(nonce, fwd.AddrType.NATIVE)),
              psbt.PsbtTxOut(amount=20_000, script=spk(nonce, fwd.AddrType.TAPROOT))),
        locktime=0)
    unsigned = psbt.PsbtTransaction(
        version=2,
        vin=(psbt.PsbtTxIn(txhash=prev.id(), n=0, script=b'',
                           sequence=PSBT_RBF, witness=()),
             psbt.PsbtTxIn(txhash=b'\x22' * 32, n=1, script=b'',
                           sequence=PSBT_RBF, witness=()),
             psbt.PsbtTxIn(txhash=b'\x33' * 32, n=0, script=b'',
                           sequence=PSBT_RBF, witness=())),
        vout=(psbt.PsbtTxOut(amount=10_000, script=spk(5, fwd.AddrType.NATIVE)),),
        locktime=0)
    inputs = [
        psbt.CreateInput(amount=60_000,
                         script_pubkey=spk(nonce, fwd.AddrType.LEGACY),
                         prev_tx=prev),
        psbt.CreateInput(amount=30_000,
                         script_pubkey=spk(nonce, fwd.AddrType.NATIVE),
                         prev_tx=None),
        psbt.CreateInput(amount=20_000,
                         script_pubkey=spk(nonce, fwd.AddrType.TAPROOT),
                         prev_tx=None),
    ]
    return psbt.create_psbt(unsigned_tx=unsigned, inputs=inputs)


def _psbt_replay(psbt, psbt_mod, seed: str, passphrase: str, kdf: str) -> tuple:
    """create -> sign -> finalize -> extract; the four stage strings
    (the mirror's `replay` helper). The Signer must sign every input."""
    unsigned = psbt_mod.to_base64(psbt=psbt)
    unsigned_list = psbt_mod.sign_psbt(seed=seed, passphrase=passphrase,
                                       kdf=kdf, psbt=psbt)
    assert unsigned_list == [], unsigned_list
    signed = psbt_mod.to_base64(psbt=psbt)
    psbt_mod.finalize_psbt(psbt=psbt)
    finalized = psbt_mod.to_base64(psbt=psbt)
    wire_hex = psbt_mod.extract_transaction(psbt=psbt).serialize_wire().hex()
    return unsigned, signed, finalized, wire_hex


def _psbt_row(mods, name: str, seed: str, nonce: int, passphrase: str,
              kdf: str, prebuilt=None) -> dict:
    """One PSBT KAT row: the tuple plus its four pipeline stages."""
    psbt_mod = mods[1]
    psbt_obj = prebuilt if prebuilt is not None else _three_forms_psbt(
        mods, seed, nonce, passphrase, kdf)
    unsigned, signed, finalized, wire_hex = _psbt_replay(
        psbt_obj, psbt_mod, seed, passphrase, kdf)
    return {
        'name': name,
        'seed': seed,
        'nonce': nonce,
        'passphrase': passphrase,
        'kdf': kdf,
        'unsigned': unsigned,
        'signed': signed,
        'finalized': finalized,
        'hex': wire_hex,
        'provenance': 'yubtc-python reference (psbt.py)',
    }


def build_psbt_vectors(python_src: Path) -> dict:
    """Build the PSBT KAT document: 16 three-forms pipeline rows (one
    per (seed, passphrase, KDF, nonce) tuple of the address matrix),
    the unknown-fields variant and the combine pair."""
    import sys
    sys.path.insert(0, str(python_src))
    # locate_reference may have probed an importable `yubtc` (e.g. a
    # pip-installed checkout without the psbt mirror); drop it so the
    # import below re-resolves against `python_src`.
    for stale in [m for m in sys.modules
                  if m == 'yubtc' or m.startswith('yubtc.')]:
        del sys.modules[stale]
    from yubtc import crypto, fwd, hash as hash_, psbt, script
    mods = (crypto, psbt, fwd, hash_, script)

    rows = []
    for kdf in KDFS:
        passphrase = PASSPHRASE_EMPTY if kdf == 'yubtc' else PASSPHRASE_NON_EMPTY
        for nonce in NONCES:
            for seed in SEEDS:
                rows.append(_psbt_row(mods, 'three_forms', seed, nonce,
                                      passphrase, kdf))

    # The variant rows anchor on the first matrix tuple (yubtc cascade,
    # nonce 0, the BIP-39 mnemonic) -- same anchor as RUST_ROWS.
    anchor = (SEEDS[0], NONCES[0], PASSPHRASE_EMPTY, 'yubtc')
    a_seed, a_nonce, a_pass, a_kdf = anchor

    # Unknown-fields variant: three opaque pairs injected into the
    # global map, input 1 and output 0 *before* the pipeline; every
    # stage must carry them byte-for-byte and the wire tx must not
    # change.
    injected = _three_forms_psbt(mods, a_seed, a_nonce, a_pass, a_kdf)
    for where, key, value in PSBT_UNKNOWN_INJECTIONS:
        kv = psbt.UnknownKv(key=key, value=value)
        if where == 'global':
            injected.unknown_global.append(kv)
        elif where == 'input':
            injected.inputs[1].unknown.append(kv)
        else:
            injected.outputs[0].unknown.append(kv)
    unknown_row = _psbt_row(mods, 'unknown_fields', a_seed, a_nonce,
                            a_pass, a_kdf, prebuilt=injected)
    # The wire transaction is blind to the extra pairs: byte-identical
    # to the clean three-forms row of the same tuple.
    clean = next(r for r in rows
                 if (r['seed'], r['nonce'], r['passphrase'], r['kdf'])
                 == anchor)
    assert unknown_row['hex'] == clean['hex']

    # Combine pair: `a` = the signed three-forms container; `combined`
    # = the merge with a synthetic disjoint-signer PARTIAL_SIG on
    # input 0 plus one extra unknown global pair (different keys of
    # one type are all kept).
    signed_only = _three_forms_psbt(mods, a_seed, a_nonce, a_pass, a_kdf)
    assert psbt.sign_psbt(seed=a_seed, passphrase=a_pass, kdf=a_kdf,
                          psbt=signed_only) == []
    assert psbt.to_base64(psbt=signed_only) == clean['signed']
    a_b64 = psbt.to_base64(psbt=signed_only)
    b = psbt.from_base64(s=a_b64)
    b.inputs[0].partial_sigs.append((PSBT_COMBINE_SYNTHETIC_PUBKEY,
                                     PSBT_COMBINE_SYNTHETIC_SIG))
    b.unknown_global.append(psbt.UnknownKv(
        key=PSBT_COMBINE_SYNTHETIC_UNKNOWN[0],
        value=PSBT_COMBINE_SYNTHETIC_UNKNOWN[1]))
    combined = psbt.combine_psbt(psbt=signed_only, other=b)

    return {
        'generator': 'core/tests/kat/generate.py',
        'reference_repo': 'yubtc-python',
        'reference_commit': reference_commit(python_src),
        'vector_count': len(rows),
        'matrix': '16 tuples = 4 KDFs x 2 nonces x 2 seeds (the same '
                  'matrix as vectors.json; passphrase forced by kdf -- '
                  'empty for yubtc, "hunter2" for the rest); each row '
                  'is the three-forms fixture (legacy P2PKH with '
                  'NON_WITNESS_UTXO + native P2WPKH + taproot P2TR, '
                  'all keyed at the row nonce) through create -> '
                  'sign -> finalize -> extract; anchored on the first '
                  'tuple: one unknown_fields variant (opaque pairs in '
                  'global/input/output maps survive the pipeline '
                  'byte-for-byte; the wire tx is unchanged) and one '
                  'combine pair (a = signed container, combined = '
                  'merge with a synthetic disjoint-signer PARTIAL_SIG '
                  '33x02/64xbb on input 0 + unknown global '
                  '5107=09)',
        'provenance': {'psbt': 'yubtc-python reference (psbt.py '
                               'mirror, direct parity since Rust '
                               '3f97d66)'},
        'vectors': rows,
        'unknown_fields': unknown_row,
        'combine': {
            'seed': a_seed,
            'nonce': a_nonce,
            'passphrase': a_pass,
            'kdf': a_kdf,
            'a': a_b64,
            'combined': psbt.to_base64(psbt=combined),
        },
    }


# --- Multi-sig axis (Phase 15) --------------------------------------------

# The ms fixture family of the mirror's `tests/test_multisig.py` (the
# `MS_SEED` / `MS_WALLET_SEED` constants): two seeds, cascade KDF,
# empty passphrase. The own key at `own_nonce` is the legacy form
# (R-MS-6, ОВ-10); the quorum is 2-of-3 over the seed's keys at
# nonces {w, w+1, w+2}.
MS_SEEDS = ['phase15multisig', 'phase15wallet']
MS_OWN_NONCES = list(range(8))

# Fixture amounts of `tests/test_multisig.py::ms_prev_tx` /
# `ms_unsigned_tx` (prev output / spend amount), sat.
MS_PREV_AMOUNT = 60_000
MS_SPEND_AMOUNT = 50_000

# The spend destination: the row seed's native-P2WPKH key at this
# nonce (fixture `ms_dst_spk` design -- on the anchor row it equals
# the mirror's pinned rows bit-for-bit).
MS_DST_NONCE = 9


def _ms_key(crypto, seed: str, nonce: int):
    """Legacy-form key at `nonce` (the mirror's `ms_key`)."""
    return crypto.seed2privkey(seed=seed, nonce=nonce, passphrase='',
                               kdf='yubtc')


def _ms_pub(crypto, seed: str, nonce: int) -> bytes:
    from yubtc.crypto import privkey2pubkey
    return privkey2pubkey(_ms_key(crypto, seed, nonce))


def _ms_row(wallet, psbt_mod, crypto, seed: str, own_nonce: int,
            key_nonces: list) -> dict:
    """One multi-sig KAT row: the (N, M, keys, nonce) tuple plus the
    quorum constants and the five-stage 2-of-3 PSBT pipeline."""
    from yubtc.hash import hash160
    from yubtc.script import (make_p2sh_lock_script, make_p2wpkh_lock_script)
    from yubtc.psbt import (CreateInput, PsbtTransaction, PsbtTxIn,
                            PsbtTxOut, combine_psbt, create_psbt,
                            extract_transaction, finalize_psbt,
                            sign_psbt_input, to_base64)

    n, m = 3, 2
    quorum_order = [own_nonce] + [k for k in key_nonces if k != own_nonce]
    # Rotated input order (R-MS-4: ms_create_address sorts; the row
    # pins the canonical output while exercising a scrambled input).
    rot = own_nonce % 3
    input_order = quorum_order[rot:] + quorum_order[:rot]
    keys = [_ms_pub(crypto, seed, k) for k in input_order]

    # Wallet-level quorum derivation: address + canonical redeem.
    # The P2SH form is explicit (the v0.3 mirror API has no default);
    # the pinned output is identical to the pre-v0.3 rows.
    addr, redeem = wallet.ms_create_address(n=n, m=m, keys=keys,
                                            form='p2sh')
    spk = bytes(make_p2sh_lock_script(hash160=hash160(redeem)))

    # Fixture: prev tx pays the quorum, the spend targets the row
    # seed's native-P2WPKH at MS_DST_NONCE.
    dst_pub = _ms_pub(crypto, seed, MS_DST_NONCE)
    dst_spk = bytes(make_p2wpkh_lock_script(hash160=hash160(dst_pub)))
    prev = PsbtTransaction(version=2,
                           vin=(PsbtTxIn(txhash=b'\x22' * 32, n=0,
                                         script=b'', sequence=0xffffffff,
                                         witness=()),),
                           vout=(PsbtTxOut(amount=MS_PREV_AMOUNT,
                                           script=spk),), locktime=0)
    unsigned_tx = PsbtTransaction(
        version=2,
        vin=(PsbtTxIn(txhash=prev.id(), n=0, script=b'',
                      sequence=0xfffffffe, witness=()),),
        vout=(PsbtTxOut(amount=MS_SPEND_AMOUNT, script=dst_spk),),
        locktime=0)
    inputs = [CreateInput(amount=MS_PREV_AMOUNT, script_pubkey=spk,
                          prev_tx=prev, redeem_script=redeem)]

    # Stage 1-2: Creator container, then the own key signs (Creator +
    # Signer in one step -- the `ms send` shape, ОВ-12).
    psbt_a = create_psbt(unsigned_tx=unsigned_tx, inputs=inputs)
    unsigned = to_base64(psbt=psbt_a)
    assert sign_psbt_input(psbt=psbt_a, index=0,
                           privkey=_ms_key(crypto, seed, own_nonce))
    signed_a = to_base64(psbt=psbt_a)

    # Stage 3-4: the first cosigner signs a fresh copy; Combiner.
    psbt_b = create_psbt(unsigned_tx=unsigned_tx, inputs=inputs)
    cosigner_nonce = next(k for k in input_order if k != own_nonce)
    assert sign_psbt_input(psbt=psbt_b, index=0,
                           privkey=_ms_key(crypto, seed, cosigner_nonce))
    combined = combine_psbt(psbt=psbt_a, other=psbt_b)
    signed_ab = to_base64(psbt=combined)

    # Stage 5: Finalizer + Extractor.
    finalize_psbt(psbt=combined)
    finalized = to_base64(psbt=combined)
    tx = extract_transaction(psbt=combined)
    wire_hex = tx.serialize_wire().hex()

    return {
        'name': 'two_of_three',
        'seed': seed,
        'kdf': 'yubtc',
        'own_nonce': own_nonce,
        'key_nonces': list(input_order),
        'n': n,
        'm': m,
        'dst_nonce': MS_DST_NONCE,
        'dst_form': 'native',
        'redeem_hex': redeem.hex(),
        'address': addr,
        'script_pubkey_hex': spk.hex(),
        'unsigned': unsigned,
        'signed_a': signed_a,
        'signed_ab': signed_ab,
        'combined': signed_ab,
        'finalized': finalized,
        'wire_hex': wire_hex,
        'txid': tx.id().hex(),
        'scriptsig_len': len(tx.vin[0].script),
        'provenance': 'yubtc-python reference (wallet.ms_create_address '
                      '+ psbt.py P2SH-multisig branches)',
    }


def _ms_witness_row(wallet, psbt_mod, crypto, seed: str, own_nonce: int,
                    key_nonces: list) -> dict:
    """One P2WSH (v0.3) multi-sig KAT row: the same (N, M, keys,
    nonce) tuple and fixture amounts as `_ms_row`, addressed in the
    native witness form -- `bc1q...` v0 with the 32-byte
    `SHA256(redeem)` program -- and replayed through the mirror's
    P2WSH-multisig PSBT branches (WITNESS_UTXO + WITNESS_SCRIPT
    Creator, BIP-143 Signer with scriptCode = redeem, witness-stack
    Finalizer)."""
    from yubtc.hash import hash160, sha256 as _sha256
    from yubtc.psbt import (CreateInput, PsbtTransaction, PsbtTxIn,
                            PsbtTxOut, combine_psbt, create_psbt,
                            extract_transaction, finalize_psbt,
                            sign_psbt_input, to_base64)
    from yubtc.script import (make_p2sh_lock_script,
                              make_p2wpkh_lock_script,
                              make_p2wsh_lock_script)

    n, m = 3, 2
    quorum_order = [own_nonce] + [k for k in key_nonces if k != own_nonce]
    rot = own_nonce % 3
    input_order = quorum_order[rot:] + quorum_order[:rot]
    keys = [_ms_pub(crypto, seed, k) for k in input_order]

    # Wallet-level quorum derivation in the witness form: the redeem
    # script is identical to the P2SH row of the same tuple; only the
    # commitment/address differ.
    addr, redeem = wallet.ms_create_address(n=n, m=m, keys=keys,
                                            form='p2wsh')
    spk = bytes(make_p2wsh_lock_script(sha256=_sha256(redeem)))
    assert bytes(make_p2sh_lock_script(hash160=hash160(redeem))) \
        != spk

    # Fixture: prev tx pays the P2WSH quorum, the spend targets the
    # row seed's native-P2WPKH at MS_DST_NONCE (same as the P2SH
    # rows).
    dst_pub = _ms_pub(crypto, seed, MS_DST_NONCE)
    dst_spk = bytes(make_p2wpkh_lock_script(hash160=hash160(dst_pub)))
    prev = PsbtTransaction(version=2,
                           vin=(PsbtTxIn(txhash=b'\x22' * 32, n=0,
                                         script=b'', sequence=0xffffffff,
                                         witness=()),),
                           vout=(PsbtTxOut(amount=MS_PREV_AMOUNT,
                                           script=spk),), locktime=0)
    # The witness form commits no prev tx: BIP-143 commits the amount
    # via WITNESS_UTXO, so the Creator branch takes witness_script
    # and prev_tx=None.
    unsigned_tx = PsbtTransaction(
        version=2,
        vin=(PsbtTxIn(txhash=b'\x44' * 32, n=0, script=b'',
                      sequence=0xfffffffe, witness=()),),
        vout=(PsbtTxOut(amount=MS_SPEND_AMOUNT, script=dst_spk),),
        locktime=0)
    inputs = [CreateInput(amount=MS_PREV_AMOUNT, script_pubkey=spk,
                          prev_tx=None, witness_script=redeem)]

    # Stage 1-2: Creator container, then the own key signs (Creator +
    # Signer in one step -- the `ms send` shape, ОВ-12).
    psbt_a = create_psbt(unsigned_tx=unsigned_tx, inputs=inputs)
    unsigned = to_base64(psbt=psbt_a)
    assert sign_psbt_input(psbt=psbt_a, index=0,
                           privkey=_ms_key(crypto, seed, own_nonce))
    signed_a = to_base64(psbt=psbt_a)

    # Stage 3-4: the first cosigner signs a fresh copy; Combiner.
    psbt_b = create_psbt(unsigned_tx=unsigned_tx, inputs=inputs)
    cosigner_nonce = next(k for k in input_order if k != own_nonce)
    assert sign_psbt_input(psbt=psbt_b, index=0,
                           privkey=_ms_key(crypto, seed, cosigner_nonce))
    combined = combine_psbt(psbt=psbt_a, other=psbt_b)
    signed_ab = to_base64(psbt=combined)

    # Stage 5: Finalizer + Extractor. The finalized input carries the
    # BIP-141 stack: M + 2 items (empty dummy, M sigs, redeem).
    finalize_psbt(psbt=combined)
    finalized = to_base64(psbt=combined)
    tx = extract_transaction(psbt=combined)
    wire_hex = tx.serialize_wire().hex()
    witness_items = len(tx.vin[0].witness)
    assert tx.vin[0].script == b''
    assert witness_items == m + 2
    assert tx.vin[0].witness[0] == b''
    assert tx.vin[0].witness[-1] == redeem

    return {
        'name': 'two_of_three_witness',
        'seed': seed,
        'kdf': 'yubtc',
        'own_nonce': own_nonce,
        'key_nonces': list(input_order),
        'n': n,
        'm': m,
        'dst_nonce': MS_DST_NONCE,
        'dst_form': 'native',
        'form': 'p2wsh',
        'redeem_hex': redeem.hex(),
        'address': addr,
        'script_pubkey_hex': spk.hex(),
        'unsigned': unsigned,
        'signed_a': signed_a,
        'signed_ab': signed_ab,
        'combined': signed_ab,
        'finalized': finalized,
        'wire_hex': wire_hex,
        'txid': tx.id().hex(),
        'witness_items': witness_items,
        'provenance': 'yubtc-python reference (wallet.ms_create_address '
                      '+ psbt.py P2WSH-multisig branches, v0.3)',
    }


def _ms_tapscript_row(wallet, psbt_mod, crypto, seed: str, own_nonce: int,
                      key_nonces: list) -> dict:
    """One P2TR script-path (v0.3) multi-sig KAT row: the same (N, M,
    keys, nonce) tuple and fixture amounts as `_ms_row`, addressed in
    the tapscript form -- `bc1p...` bech32m v1 with the tweaked NUMS
    output key of the canonical tapscript -- and replayed through the
    mirror's P2TR script-path PSBT branches (WITNESS_UTXO +
    TAP_LEAF_SCRIPT + TAP_INTERNAL_KEY Creator, BIP-341 script-path
    Signer with the untweaked BIP-340 key, R-MS-11 witness-stack
    Finalizer). Mirrors the parity fixture
    `tests/fixtures/tapscript_ms_rows.json` row for row."""
    from yubtc.crypto import (tapscript_control_block,
                              tapscript_output_key)
    from yubtc.fwd import MS_TAPSCRIPT_INTERNAL_KEY
    from yubtc.hash import hash160
    from yubtc.psbt import (CreateInput, PsbtTransaction, PsbtTxIn,
                            PsbtTxOut, combine_psbt, create_psbt,
                            extract_transaction, finalize_psbt,
                            sign_psbt_input, to_base64)
    from yubtc.script import (TAPSCRIPT_LEAF_VERSION,
                              make_p2wpkh_lock_script,
                              tapscript_leaf_hash)
    from yubtc.transaction import (SpendInput,
                                   taproot_scriptpath_sighash,
                                   taproot_sign_sighash_untweaked)
    from yubtc.wallet import ms_quorum_lock_script

    n, m = 3, 2
    quorum_order = [own_nonce] + [k for k in key_nonces if k != own_nonce]
    rot = own_nonce % 3
    input_order = quorum_order[rot:] + quorum_order[:rot]
    keys = [_ms_pub(crypto, seed, k) for k in input_order]

    # Wallet-level quorum derivation in the tapscript form: the redeem
    # is the R-MS-7 CHECKSIGADD tapscript over the x-only projections
    # of the sorted keys (a *different* script than the p2sh/p2wsh
    # redeem of the same tuple, R-MS-10); the address commits to the
    # tweaked NUMS output key of that tapscript.
    addr, redeem = wallet.ms_create_address(n=n, m=m, keys=keys,
                                            form='p2tr')
    spk = bytes(ms_quorum_lock_script(redeem=redeem, form='p2tr'))
    leaf_hash = tapscript_leaf_hash(script=redeem)
    output_key = tapscript_output_key(
        internal_xonly=MS_TAPSCRIPT_INTERNAL_KEY, leaf_hash=leaf_hash)
    control = tapscript_control_block(
        internal_xonly=MS_TAPSCRIPT_INTERNAL_KEY, leaf_hash=leaf_hash)
    assert len(control) == 33 and control[0] & 0xfe == 0xc0
    assert control[1:] == MS_TAPSCRIPT_INTERNAL_KEY
    assert spk == b'\x51\x20' + output_key

    # Fixture: prev tx pays the P2TR quorum, the spend targets the row
    # seed's native-P2WPKH at MS_DST_NONCE (same as the P2SH/P2WSH
    # rows). The tapscript form commits no prev tx: BIP-341 commits
    # the amount via WITNESS_UTXO, so the outpoint is the synthetic
    # [0x44; 32] of the witness-row fixture.
    dst_pub = _ms_pub(crypto, seed, MS_DST_NONCE)
    dst_spk = bytes(make_p2wpkh_lock_script(hash160=hash160(dst_pub)))
    prev = PsbtTransaction(version=2,
                           vin=(PsbtTxIn(txhash=b'\x22' * 32, n=0,
                                         script=b'', sequence=0xffffffff,
                                         witness=()),),
                           vout=(PsbtTxOut(amount=MS_PREV_AMOUNT,
                                           script=spk),), locktime=0)
    unsigned_tx = PsbtTransaction(
        version=2,
        vin=(PsbtTxIn(txhash=b'\x44' * 32, n=0, script=b'',
                      sequence=0xfffffffe, witness=()),),
        vout=(PsbtTxOut(amount=MS_SPEND_AMOUNT, script=dst_spk),),
        locktime=0)
    inputs = [CreateInput(amount=MS_PREV_AMOUNT, script_pubkey=spk,
                          prev_tx=None,
                          tap_leaf_script=redeem
                          + bytes([TAPSCRIPT_LEAF_VERSION]))]

    # The pinned own digest/signature: the BIP-341 script-path sighash
    # (SigMsg spend_type 0x02 extended by the leaf hash,
    # SIGHASH_DEFAULT) and the untweaked BIP-340 Schnorr signature
    # over it (deterministic, aux_rand = 0x00 x 32) -- the digest the
    # Signer branch signs and the signature it inserts.
    sighash = taproot_scriptpath_sighash(
        tx=unsigned_tx, input_index=0,
        spend=[SpendInput(amount=MS_PREV_AMOUNT, script_pubkey=spk)],
        leaf_hash=leaf_hash)
    own_sig = taproot_sign_sighash_untweaked(
        privkey=_ms_key(crypto, seed, own_nonce), sighash=sighash)
    assert len(own_sig) == 64

    # Stage 1-2: Creator container, then the own key signs (Creator +
    # Signer in one step -- the `ms send` shape, ОВ-12).
    psbt_a = create_psbt(unsigned_tx=unsigned_tx, inputs=inputs)
    unsigned = to_base64(psbt=psbt_a)
    assert sign_psbt_input(psbt=psbt_a, index=0,
                           privkey=_ms_key(crypto, seed, own_nonce))
    # The inserted TAP_SCRIPT_SIG is exactly the pinned digest +
    # signature pair.
    inserted = [s.sig for s in psbt_a.inputs[0].tap_script_sigs
                if s.leaf_hash == leaf_hash]
    assert inserted == [own_sig]
    signed_a = to_base64(psbt=psbt_a)

    # Stage 3-4: the first cosigner signs a fresh copy; Combiner.
    psbt_b = create_psbt(unsigned_tx=unsigned_tx, inputs=inputs)
    cosigner_nonce = next(k for k in input_order if k != own_nonce)
    assert sign_psbt_input(psbt=psbt_b, index=0,
                           privkey=_ms_key(crypto, seed, cosigner_nonce))
    combined = combine_psbt(psbt=psbt_a, other=psbt_b)
    signed_ab = to_base64(psbt=combined)

    # Stage 5: Finalizer + Extractor. The finalized input carries the
    # R-MS-11 stack: N + 2 items (N signature slots in reverse script
    # order, non-signers riding as empty items, no CHECKMULTISIG
    # dummy; the tapscript; the 33-byte control block).
    finalize_psbt(psbt=combined)
    finalized = to_base64(psbt=combined)
    # The serialized FINAL_SCRIPTWITNESS value (compact_size count +
    # items): 1 + (1+64) x M + (1+0) x (N-M) + (1+104) + (1+33) = 271
    # for the fixed 2-of-3 fixture (the R-MS-11 worst-case size pin).
    final_scriptwitness_len = len(combined.inputs[0].final_scriptwitness)
    tx = extract_transaction(psbt=combined)
    wire_hex = tx.serialize_wire().hex()
    witness_items = len(tx.vin[0].witness)
    assert tx.vin[0].script == b''
    assert witness_items == n + 2
    assert tx.vin[0].witness[-1] == control
    assert tx.vin[0].witness[-2] == redeem
    assert final_scriptwitness_len == 271

    return {
        'name': 'two_of_three_tapscript',
        'seed': seed,
        'kdf': 'yubtc',
        'own_nonce': own_nonce,
        'key_nonces': list(input_order),
        'n': n,
        'm': m,
        'dst_nonce': MS_DST_NONCE,
        'dst_form': 'native',
        'form': 'p2tr',
        'internal_hex': MS_TAPSCRIPT_INTERNAL_KEY.hex(),
        'leaf_hash_hex': leaf_hash.hex(),
        'output_key_hex': output_key.hex(),
        'control_hex': control.hex(),
        'redeem_hex': redeem.hex(),
        'address': addr,
        'script_pubkey_hex': spk.hex(),
        'sighash_hex': sighash.hex(),
        'own_sig_hex': own_sig.hex(),
        'unsigned': unsigned,
        'signed_a': signed_a,
        'signed_ab': signed_ab,
        'combined': signed_ab,
        'finalized': finalized,
        'wire_hex': wire_hex,
        'txid': tx.id().hex(),
        'witness_items': witness_items,
        'witness_stack_hex': [w.hex() for w in tx.vin[0].witness],
        'final_scriptwitness_len': final_scriptwitness_len,
        'provenance': 'yubtc-python reference (wallet.ms_create_address '
                      '+ ms_quorum_lock_script + psbt.py P2TR '
                      'script-path branches, v0.3)',
    }


def build_ms_vectors(python_src: Path) -> dict:
    """Build the multi-sig KAT document: 16 (N, M, keys, nonce) tuples
    (2 seeds x 8 own-nonces), each with the quorum constants and the
    2-of-3 five-stage PSBT pipeline, plus the v0.3 witness variants of
    the same 16 tuples: the native P2WSH form and the P2TR script-path
    form, each through its mirror PSBT branches."""
    import sys
    sys.path.insert(0, str(python_src))
    # locate_reference may have probed an importable `yubtc` (e.g. a
    # pip-installed checkout without the multisig mirror); drop it so
    # the import below re-resolves against `python_src`.
    for stale in [m for m in sys.modules
                  if m == 'yubtc' or m.startswith('yubtc.')]:
        del sys.modules[stale]
    from yubtc import crypto, psbt, wallet
    if not hasattr(wallet, 'ms_create_psbt'):
        raise SystemExit('error: the yubtc-python reference at '
                         f'{python_src} lacks the Phase 15 multisig '
                         'mirror (wallet.ms_create_psbt); pass '
                         '--python-src pointing at the issue-multisig '
                         'checkout')
    from yubtc.script import make_multisig_tapscript
    if not hasattr(make_multisig_tapscript, '__call__'):
        raise SystemExit('error: the yubtc-python reference at '
                         f'{python_src} lacks the v0.3 tapscript '
                         'mirror (script.make_multisig_tapscript); '
                         'pass --python-src pointing at the '
                         'issue-tapscript-ms checkout')

    rows = []
    witness_rows = []
    tapscript_rows = []
    for seed in MS_SEEDS:
        for own_nonce in MS_OWN_NONCES:
            # Quorum derivation nonces {w, w+1, w+2}; the row stores
            # the rotated input order.
            key_nonces = [own_nonce, own_nonce + 1, own_nonce + 2]
            rows.append(_ms_row(wallet, psbt, crypto, seed, own_nonce,
                                key_nonces))
            # v0.3: the same tuple through the P2WSH witness branches.
            # The redeem script must be byte-identical to the P2SH
            # row's -- only the commitment/address differ.
            witness = _ms_witness_row(wallet, psbt, crypto, seed,
                                      own_nonce, key_nonces)
            assert witness['redeem_hex'] == rows[-1]['redeem_hex']
            witness_rows.append(witness)
            # v0.3: the same tuple through the P2TR script-path
            # branches. The redeem is the R-MS-7 tapscript over the
            # x-only projections -- a *different* script than the
            # p2sh/p2wsh redeem (R-MS-10), hence a different
            # commitment.
            tap = _ms_tapscript_row(wallet, psbt, crypto, seed,
                                    own_nonce, key_nonces)
            assert tap['redeem_hex'] != rows[-1]['redeem_hex']
            assert tap['redeem_hex'] != witness['redeem_hex']
            assert tap['address'].startswith('bc1p')
            tapscript_rows.append(tap)

    return {
        'generator': 'core/tests/kat/generate.py',
        'reference_repo': 'yubtc-python',
        'reference_commit': reference_commit(python_src),
        'vector_count': len(rows),
        'witness_vector_count': len(witness_rows),
        'tapscript_vector_count': len(tapscript_rows),
        'matrix': '16 tuples = 2 seeds x 8 own-nonces (0..7); cascade '
                  'KDF, empty passphrase (the mirror fixture family '
                  'of tests/test_multisig.py); quorum = 2-of-3 over '
                  'the seed legacy keys at nonces {w, w+1, w+2} '
                  '(R-MS-6/ОВ-10), keys passed in the row-rotated '
                  'order so ms_create_address exercises the R-MS-4 '
                  'sort; each row pins address/redeem_hex/'
                  'script_pubkey_hex plus the five-stage pipeline '
                  'unsigned -> signed_a (own key) -> combined (first '
                  'cosigner) -> signed_ab/combined -> finalized + '
                  'wire_hex/txid/scriptsig_len; prev tx pays 60_000 '
                  'sat to the P2SH quorum ([0x22;32] outpoint), the '
                  'spend goes to the row seed native-P2WPKH at nonce '
                  '9 for 50_000 sat',
        'witness_matrix': 'the SAME 16 tuples in the native '
                          'P2WSH form (specs/spec.md «Multi-sig»): the '
                          'redeem script is byte-identical to the '
                          'P2SH row of the tuple, the address is '
                          'bech32 v0/32 SHA256(redeem); the prev tx '
                          '([0x22;32] outpoint) pays the P2WSH lock '
                          'script, the Creator writes WITNESS_UTXO + '
                          'WITNESS_SCRIPT (no prev-tx fetch -- '
                          'BIP-143 commits the amount), the Finalizer '
                          'emits the BIP-141 stack [empty dummy, '
                          'M sigs, redeem] (witness_items = M + 2 = '
                          '4), each row pins the five-stage pipeline '
                          '+ wire_hex/txid/witness_items',
        'tapscript_matrix': 'the SAME 16 tuples in the P2TR '
                            'script-path form (specs/spec.md «Multi-sig»): '
                            'the redeem '
                            'is the R-MS-7 CHECKSIGADD tapscript over '
                            'the x-only key projections (a different '
                            'script than the p2sh/p2wsh redeem, '
                            'R-MS-10), the address is bech32m v1 over '
                            'the tweaked NUMS output key '
                            '(internal_hex pins the NUMS key = '
                            'SHA256(uncompressed G)); the synthetic '
                            '[0x44;32] outpoint stands for the prev '
                            'tx (BIP-341 commits the amount via '
                            'WITNESS_UTXO), the Creator writes '
                            'WITNESS_UTXO + TAP_LEAF_SCRIPT (script '
                            '‖ 0xc0) + TAP_INTERNAL_KEY, the Signer '
                            'signs the BIP-341 script-path digest '
                            '(sighash_hex) with untweaked BIP-340 '
                            '(own_sig_hex, SIGHASH_DEFAULT, '
                            'deterministic), the Finalizer emits the '
                            'R-MS-11 stack [N reversed sig slots, '
                            'non-signers empty, tapscript, 33-byte '
                            'control block] (witness_items = N + 2 = '
                            '5, final_scriptwitness_len = 271), each '
                            'row pins the crypto chain (leaf_hash_hex/'
                            'output_key_hex/control_hex) + the '
                            'five-stage pipeline + wire_hex/txid/'
                            'witness_stack_hex; mirrors the parity '
                            'fixture tapscript_ms_rows.json row for '
                            'row',
        'provenance': {'ms': 'yubtc-python reference (issue-multisig '
                             'mirror; anchor row equals '
                             'tests/test_multisig.py::MS_ROWS '
                             'bit-for-bit)',
                       'ms_witness': 'yubtc-python reference (v0.3 '
                                     'mirror; existing P2SH rows are '
                                     'byte-frozen -- a regeneration '
                                     'must not change them)',
                       'ms_tapscript': 'yubtc-python reference (v0.3 '
                                       'tapscript mirror; mirrors '
                                       'tests/fixtures/'
                                       'tapscript_ms_rows.json -- '
                                       'the Rust oracle rows -- row '
                                       'for row)'},
        'anchor': {'seed': MS_SEEDS[0], 'own_nonce': 0,
                   'note': 'equals the mirror MS_ROWS parity rows; '
                           'wire carries the 253-byte multisig '
                           'scriptSig (D-002 CompactSize pin: '
                           'fd fd 00 at bytes 41..44)'},
        'witness_anchor': {'seed': MS_SEEDS[0], 'own_nonce': 0,
                           'note': 'the P2WSH counterpart of the '
                                   'anchor tuple: same redeem script, '
                                   'bc1q v0/32 address, witness spend '
                                   'carries 4 items with the empty '
                                   'dummy first'},
        'tapscript_anchor': {'seed': MS_SEEDS[0], 'own_nonce': 0,
                             'note': 'the P2TR counterpart of the '
                                     'anchor tuple: tapscript redeem '
                                     'over the x-only projections, '
                                     'bc1p v1 address over the '
                                     'tweaked NUMS output key, '
                                     'witness spend carries 5 items '
                                     '(2 sigs, 1 empty slot, '
                                     'tapscript, control block) '
                                     'totalling 271 serialized '
                                     'FINAL_SCRIPTWITNESS bytes'},
        'vectors': rows,
        'witness_vectors': witness_rows,
        'tapscript_vectors': tapscript_rows,
    }


def frozen_parameters(crypto) -> dict:
    """The frozen KDF parameters, read from the reference itself."""
    return {
        'argon2id': {
            'salt_tag_hex': crypto.ARGON2_SALT_TAG.hex(),
            'time_cost': crypto.ARGON2_TIME_COST,
            'memory_kib': crypto.ARGON2_MEMORY_KIB,
            'parallelism': crypto.ARGON2_PARALLELISM,
            'version': '0x13',  # argon2 default v19; reference omits it
            'hash_len': crypto.STRETCH_LEN,
        },
        'scrypt': {
            'salt_tag_hex': crypto.SCRYPT_SALT_TAG.hex(),
            'log_n': crypto.SCRYPT_LOG_N,
            'r': crypto.SCRYPT_R,
            'p': crypto.SCRYPT_P,
            'dklen': crypto.STRETCH_LEN,
        },
    }


def reference_commit(python_src: Path) -> str:
    """Best-effort provenance: the reference repo's current HEAD."""
    try:
        out = subprocess.run(
            ['git', '-C', str(python_src.parent), 'rev-parse', 'HEAD'],
            capture_output=True, text=True, check=True, timeout=10)
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return 'unknown'


def locate_reference(explicit: str | None, required: str = 'crypto.py') -> Path:
    """Find a yubtc-python checkout's `src/` directory carrying
    `required` (the PSBT axis needs the `psbt.py` mirror)."""
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit).resolve())
    else:
        candidates.append(REFERENCE_SRC)
        candidates.append(PSBT_REFERENCE_SRC)
        candidates.append(MS_REFERENCE_SRC)
        candidates.append(TAPSCRIPT_REFERENCE_SRC)
        try:
            import yubtc  # noqa: PLC0415 -- already importable (pip install -e)
            candidates.append(Path(yubtc.__file__).resolve().parent.parent)
        except ImportError:
            pass
        here = Path.cwd().resolve()
        candidates += [REPO_ROOT.parent / 'yubtc-python' / 'src',
                       here / 'yubtc-python' / 'src',
                       here.parent / 'yubtc-python' / 'src']
    for cand in candidates:
        if (cand / 'yubtc' / required).is_file():
            return cand
    searched = ', '.join(str(c) for c in candidates) or '(no candidates)'
    raise SystemExit(f'error: yubtc-python source (with {required}) not '
                     f'found; searched: {searched}. Pass --python-src.')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        '--axis', choices=('address', 'psbt', 'ms', 'all'), default='all',
        help='which vector file(s) to (re)generate (default: all)')
    parser.add_argument(
        '--python-src', default=None,
        help='path to yubtc-python/src (default: auto-detect)')
    args = parser.parse_args()

    if args.axis in ('address', 'all'):
        python_src = locate_reference(args.python_src)
        sys.path.insert(0, str(python_src))
        from yubtc import crypto

        vectors = build_vectors()
        reference = 'yubtc-python reference (seed2bin/seed2privkey)'
        doc = {
            'generator': 'core/tests/kat/generate.py',
            'reference_repo': 'yubtc-python',
            'reference_commit': reference_commit(python_src),
            'vector_count': len(vectors),
            'matrix': '4 KDFs x 2 nonces x 2 seeds; passphrase forced by kdf '
                      '(empty for yubtc, "hunter2" for the rest); invalid '
                      'combinations excluded (they raise in both '
                      'implementations); each row carries all three '
                      'address forms (legacy/native/taproot) -- same key '
                      'in three encodings for yubtc/argon2id/scrypt '
                      '(вариант A), purpose-specific keys (m/44\'/84\'/86\') '
                      'for pbkdf2',
            'provenance': {kdf: reference for kdf in KDFS},
            'parameters': frozen_parameters(crypto),
            'vectors': vectors,
        }
        out_path = SCRIPT_DIR / 'vectors.json'
        out_path.write_text(
            json.dumps(doc, indent=2, ensure_ascii=False) + '\n',
            encoding='utf-8')
        print(f'wrote {out_path} ({len(vectors)} vectors)')

    if args.axis in ('psbt', 'all'):
        psbt_src = locate_reference(args.python_src, required='psbt.py')
        psbt_doc = build_psbt_vectors(psbt_src)
        psbt_path = SCRIPT_DIR / 'psbt_vectors.json'
        psbt_path.write_text(
            json.dumps(psbt_doc, indent=2, ensure_ascii=False) + '\n',
            encoding='utf-8')
        print(f'wrote {psbt_path} ({psbt_doc["vector_count"]} vectors)')

    if args.axis in ('ms', 'all'):
        ms_src = locate_reference(args.python_src, required='wallet.py')
        ms_doc = build_ms_vectors(ms_src)
        ms_path = SCRIPT_DIR / 'ms_vectors.json'
        ms_path.write_text(
            json.dumps(ms_doc, indent=2, ensure_ascii=False) + '\n',
            encoding='utf-8')
        print(f'wrote {ms_path} ({ms_doc["vector_count"]} vectors)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
