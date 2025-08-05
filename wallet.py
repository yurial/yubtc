from typing import Union
from collections import namedtuple

from fwd import MINIMAL_FEE, DEFAULT_CONFIRMATIONS
from fwd import TSatoshi, TBTC, TSeed, TAddress
from misc import unpack_address

class TPrivKey(object):
    def __init__(self, *args, privkey: bytes = None, seed: TSeed = None, nonce: int = None):
        from crypto import privwif2privkey, seed2privkey
        if args:
            raise Exception('only kwargs allowed')
        if privkey:
            self.privkey = privkey
        else:
            if not seed:
                raise Exception('seed not set')
            if nonce is None:
                raise Exception('nonce not set')
            self.privkey = seed2privkey(seed=seed, nonce=nonce)
        self.nonce = nonce
        self._info = None

    def get_privwif(self, compressed: bool = True):
        from crypto import privkey2privwif
        return privkey2privwif(privkey=self.privkey, compressed=compressed)

    def get_p2pkh_address(self, compressed: bool = True):
        from crypto import privkey2addr
        return privkey2addr(privkey=self.privkey, compressed=compressed)

    def get_info(self):
        from misc import get_address_info
        if not self._info:
            self._info = get_address_info(self.get_p2pkh_address())
        return self._info

    def is_unused(self):
        total_received = self.get_info()['total_received']
        return total_received == 0

    def get_unspent(self, confirmations: int = DEFAULT_CONFIRMATIONS):
        from misc import get_address_unspent
        result = list()
        for x in get_address_unspent(self.get_p2pkh_address()):
            if x['confirmations'] >= confirmations:
                result.append({'tx': x['tx_hash'], 'out_n': x['tx_output_n'], 'amount': x['value'], 'script': x['script']})
        return result



class Wallet(object):
    def __init__(self, *args, privkey: bytes = None, privwif: str = None, seed: TSeed = None, compressed: bool = True, nonce: int = None, new_addresses: int = 1):
        if args:
            raise Exception('only kwargs allowed')
        if privkey:
            self.privkeys = [TPrivKey(privkey=privkey)]
        elif privwif:
            privkey, compressed = privwif2privkey(privwif)
            self.privkeys = [TPrivKey(privkey=privkey)]
        elif seed:
            self.privkeys = []
            while True:
                privkey = TPrivKey(seed=seed, nonce=nonce)
                if privkey.is_unused():
                    break
                self.privkeys.append(privkey)
                nonce = nonce + 1
            for i in range(new_addresses):
                privkey = TPrivKey(seed=seed, nonce=nonce)
                self.privkeys.append(privkey)
                nonce = nonce + 1

    def send(self, *args, dst: TAddress = None, amount: TBTC = None, feekb: TSatoshi = None, fee: TBTC = None, confirmations: int = None, send: bool = None):
        from misc import yesno, satoshi2btc, btc2satoshi
        from net import sendTx
        from crypto import PREFIX_P2PKH, PREFIX_P2SH
        if args:
            raise Exception('only kwargs allowed')
        if amount is not None:
            amount = btc2satoshi(amount)
        fee = btc2satoshi(fee)
        cashback = satoshi2btc(cashback)
        amount = satoshi2btc(amount)
        fee = satoshi2btc(fee)
        tx, cashback, amount, fee = self.make_transaction(dst=dst, amount=amount, feekb=feekb, fee=fee, confirmations=confirmations)
        rawtx = tx.serialize()
        if yesno('send {:0.08f} BTC to {} (cacshback={:0.08f}, fee={:0.08f}, txsize={})? '.format(amount, dst, cashback, fee, len(rawtx))):
            print('id: {}'.format(tx.id().hex()))
            if send:
                sendTx(rawtx)
            else:
                print(rawtx.hex())

    def _make_vin(self, pubhash, unspent):
        from transaction import script2pkh, CIn
        vin = list()
        in_amount = 0
        for u in unspent:
            in_amount += u['amount']
            tx_lock_script = bytes.fromhex(u['script'])
            required_hash = script2pkh(tx_lock_script)
            if required_hash != pubhash:
                raise Exception('unknown pubkey required')
            txhash = bytes.fromhex(u['tx'])
            vin.append(CIn(txhash=txhash, n=u['out_n'], script=tx_lock_script))
        return vin, in_amount

    def _make_vout(self, pubhash, in_amount, amount, fee, vout_script):
        from transaction import COut
        from script import CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG
        if amount is None or (amount+fee == in_amount):
            amount = in_amount - fee
            return [COut(amount=amount, script=vout_script)], 0, amount
        else:
            cashback = in_amount - amount - fee
            cashback_lock_script = CScript([OP_DUP, OP_HASH160, pubhash, OP_EQUALVERIFY, OP_CHECKSIG])
            return [COut(amount=cashback, script=cashback_lock_script), COut(amount=amount, script=vout_script)], cashback, amount

    def _make_p2pkh_vout(self, pubhash, dsthash, in_amount, amount, fee):
        from transaction import COut
        from script import CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG
        vout_script = CScript([OP_DUP, OP_HASH160, dsthash, OP_EQUALVERIFY, OP_CHECKSIG])
        return self._make_vout(pubhash, in_amount, amount, fee, vout_script)

    def _make_p2sh_vout(self, pubhash, script_hash, in_amount, amount, fee):
        from transaction import COut
        from script import CScript, OP_HASH160, OP_PUSHBYTES_20, OP_EQUAL
        vout_script = CScript([OP_HASH160, script_hash, OP_EQUAL])
        return self._make_vout(pubhash, in_amount, amount, fee, vout_script)

    def make_transaction(self, dst: TAddress, amount: TBTC, feekb: TBTC = None, fee: int = None, confirmations: int = None):
        prefix, dsthash = unpack_address(dst)
        if prefix == PREFIX_P2PKH:
            return self.make_p2pkh_transaction(dsthash=dsthash, amount=amount, feekb=feekb, fee=fee, confirmations=confirmations)
        elif prefix == PREFIX_P2SH:
            return self.make_p4sh_transaction(script_hash=dsthash, amount=amount, feekb=feekb, fee=fee, confirmations=confirmations)
        else:
            raise Exception('address not supported')

    def make_p2pkh_transaction(self, dsthash, amount, feekb=MINIMAL_FEE, fee=0, confirmations=6):
        from hash import hash160
        from crypto import privkey2pubkey, pubkey2pubwif, sign_data
        from transaction import CTransaction
        pubkey = privkey2pubkey(self.privkeys[0].privkey)
        pubwif = pubkey2pubwif(pubkey)
        pubhash = hash160(pubwif)
        unspent = self.privkeys[0].get_unspent(confirmations=confirmations)
        vin, in_amount = self._make_vin(pubhash=pubhash, unspent=unspent)
        _fee = fee
        while True:
            vout, _cashback, _amount = self._make_p2pkh_vout(pubhash=pubhash, dsthash=dsthash, in_amount=in_amount, amount=amount, fee=_fee)
            tx = CTransaction(vin=vin, vout=vout)
            stx = tx.sign(privkey=self.privkeys[0].privkey, pubwif=pubwif)
            if fee != 0:
                break
            txsize = len(stx.serialize())
            newfee = int(txsize * feekb / 1000)
            if _fee == newfee:
                break;
            _fee = newfee

        return stx, _cashback, _amount, _fee

    def make_p2sh_transaction(self, script_hash, amount, feekb=MINIMAL_FEE, fee=0, confirmations=6):
        from hash import hash160
        from crypto import privkey2pubkey, pubkey2pubwif, sign_data
        from transaction import CTransaction
        pubkey = privkey2pubkey(self.privkeys[0].privkey)
        pubwif = pubkey2pubwif(pubkey)
        pubhash = hash160(pubwif)
        unspent = self.privkeys[0].get_unspent(confirmations=confirmations)
        vin, in_amount = self._make_vin(pubhash=pubhash, unspent=unspent)
        _fee = fee
        while True:
            vout, _cashback, _amount = self._make_p2sh_vout(pubhash=pubhash, script_hash=script_hash, in_amount=in_amount, amount=amount, fee=_fee)
            tx = CTransaction(vin=vin, vout=vout)
            stx = tx.sign(privkey=self.privkeys[0].privkey, pubwif=pubwif)
            if fee != 0:
                break
            txsize = len(stx.serialize())
            newfee = int(txsize * feekb / 1000)
            if _fee == newfee:
                break;
            _fee = newfee

        return stx, _cashback, _amount, _fee
