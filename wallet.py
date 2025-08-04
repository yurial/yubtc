from collections import namedtuple
from decimal import Decimal
MINIMAL_FEE = 1000


class TAddress(object):
    def __init__(self, *args, privkey=None):
        if args:
            raise Exception('only kwargs allowed')
        if not privkey:
            raise Exception('privkey not set')
        self.privkey = privkey

    def get_privwif(self, compressed=True):
        from crypto import privkey2privwif
        return privkey2privwif(privkey=self.privkey, compressed=compressed)

    def get_p2pkh_address(self, compressed=True):
        from crypto import privkey2addr
        return privkey2addr(privkey=self.privkey, compressed=compressed)


class Wallet(object):
    def __init__(self, *args, privkey=None, privwif=None, seed=None, compressed=True, nonce=0):
        from crypto import privwif2privkey, seed2privkey
        if args:
            raise Exception('only kwargs allowed')
        if privkey:
            self.addresses = [TAddress(privkey=privkey)]
        elif privwif:
            privkey, compressed = privwif2privkey(privwif)
            self.addresses = [TAddress(privkey=privkey)]
        elif seed:
            privkey = seed2privkey(seed=seed, nonce=nonce)
            self.addresses = [TAddress(privkey=privkey)]

    def get_unspent(self, confirmations=6):
        from misc import get_unspent
        result = list()
        for x in get_unspent(self.addresses[0].get_p2pkh_address()):
            if x['confirmations'] >= confirmations:
                result.append({'tx': x['tx_hash'], 'out_n': x['tx_output_n'], 'amount': x['value'], 'script': x['script']})
        return result

    def send(self, dst, amount, feekb=MINIMAL_FEE, fee=Decimal(0), confirmations=6, dump=True):
        from misc import yesno, satoshi2btc, btc2satoshi
        from net import sendTx
        from base58check import base58CheckDecode
        from crypto import PREFIX_P2PKH, PREFIX_P2SH
        if amount is not None:
            if not isinstance(amount, Decimal):
                raise Exception('amount should be a instance of Decimal type')
            amount = btc2satoshi(amount)
        if not isinstance(fee, Decimal):
            raise Exception('fee should be a instance of Decimal type')
        fee = btc2satoshi(fee)
        if dst is None:
            dst = self.addresses[0].get_p2pkh_address()
        data = base58CheckDecode(dst)
        prefix = data[0]
        dsthash = data[1:]
        if prefix == PREFIX_P2PKH:
            tx, cashback, amount, fee = self.make_p2pkh_transaction(dsthash=dsthash, amount=amount, feekb=feekb, fee=fee, confirmations=confirmations)
        elif prefix == PREFIX_P2SH:
            tx, cashback, amount, fee = self.make_p2sh_transaction(script_hash=dsthash, amount=amount, feekb=feekb, fee=fee, confirmations=confirmations)
        else:
            raise Exception('address not supported')
        cashback = satoshi2btc(cashback)
        amount = satoshi2btc(amount)
        fee = satoshi2btc(fee)
        rawtx = tx.serialize()
        if yesno('send {:0.08f} BTC to {} (cacshback={:0.08f}, fee={:0.08f}, txsize={})? '.format(amount, dst, cashback, fee, len(rawtx))):
            print('id: {}'.format(tx.id().hex()))
            if dump:
                print(rawtx.hex())
            else:
                sendTx(rawtx)

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

    def make_p2pkh_transaction(self, dsthash, amount, feekb=MINIMAL_FEE, fee=0, confirmations=6):
        from hash import hash160
        from crypto import privkey2pubkey, pubkey2pubwif, sign_data
        from transaction import CTransaction
        pubkey = privkey2pubkey(self.adresses[0].privkey)
        pubwif = pubkey2pubwif(pubkey)
        pubhash = hash160(pubwif)
        unspent = self.get_unspent(confirmations=confirmations)
        vin, in_amount = self._make_vin(pubhash=pubhash, unspent=unspent)
        _fee = fee
        while True:
            vout, _cashback, _amount = self._make_p2pkh_vout(pubhash=pubhash, dsthash=dsthash, in_amount=in_amount, amount=amount, fee=_fee)
            tx = CTransaction(vin=vin, vout=vout)
            stx = tx.sign(privkey=self.adresses[0].privkey, pubwif=pubwif)
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
        pubkey = privkey2pubkey(self.adresses[0].privkey)
        pubwif = pubkey2pubwif(pubkey)
        pubhash = hash160(pubwif)
        unspent = self.get_unspent(confirmations=confirmations)
        vin, in_amount = self._make_vin(pubhash=pubhash, unspent=unspent)
        _fee = fee
        while True:
            vout, _cashback, _amount = self._make_p2sh_vout(pubhash=pubhash, script_hash=script_hash, in_amount=in_amount, amount=amount, fee=_fee)
            tx = CTransaction(vin=vin, vout=vout)
            stx = tx.sign(privkey=self.adresses[0].privkey, pubwif=pubwif)
            if fee != 0:
                break
            txsize = len(stx.serialize())
            newfee = int(txsize * feekb / 1000)
            if _fee == newfee:
                break;
            _fee = newfee

        return stx, _cashback, _amount, _fee
