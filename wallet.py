from decimal import Decimal
MINIMAL_FEE = 1000

class Wallet(object):
    def __init__(self, *args, privkey=None, privwif=None, seed=None, compressed=True, nonce=0):
        from crypto import privwif2privkey, seed2privkey
        if args:
            raise Exception('only kwargs allowed')
        self.privkey = privkey
        self.compressed = compressed
        if privwif:
            self.privkey, self.compressed = privwif2privkey(privwif)
        if seed:
            self.compressed = compressed
            self.privkey = seed2privkey(seed=seed, nonce=nonce)

    def get_compressed(self, compressed=None):
        return compressed if compressed is not None else self.compressed

    def get_privwif(self, compressed=None):
        from crypto import privkey2privwif
        return privkey2privwif(privkey=self.privkey, compressed=self.get_compressed(compressed))

    def get_p2pkh_address(self, compressed=None):
        from crypto import privkey2addr
        return privkey2addr(privkey=self.privkey, compressed=self.get_compressed(compressed))

    def get_unspent(self, confirmations=6):
        from misc import get_unspent
        result = list()
        for x in get_unspent(self.get_p2pkh_address()):
            if x['confirmations'] >= confirmations:
                result.append({'tx': x['tx_hash'], 'out_n': x['tx_output_n'], 'amount': x['value'], 'script': x['script']})
        return result

    def get_balance(self, confirmations=6):
        from misc import satoshi2btc
        in_amount = 0
        for tx in self.get_unspent(confirmations=confirmations):
            in_amount += tx['amount']
        return satoshi2btc(in_amount)

    def send(self, dst, amount, feekb=MINIMAL_FEE, fee=Decimal(0), confirmations=6):
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
            dst = self.get_p2pkh_address()
        data = base58CheckDecode(dst)
        prefix = data[0]
        dsthash = data[1:]
        if prefix != PREFIX_P2PKH:
            raise Exception('address now supported')
        tx, cashback, amount, fee = self.make_transaction(dsthash=dsthash, amount=amount, feekb=feekb, fee=fee, confirmations=confirmations)
        cashback = satoshi2btc(cashback)
        amount = satoshi2btc(amount)
        fee = satoshi2btc(fee)
        rawtx = tx.serialize()
        if yesno('send {:0.08f} BTC to {} (cacshback={:0.08f}, fee={:0.08f}, txsize={})? '.format(amount, dst, cashback, fee, len(rawtx))):
            print('id: {}'.format(tx.id().hex()))
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

    def _make_vout(self, pubhash, dsthash, in_amount, amount, fee):
        from transaction import COut
        from script import CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG
        dst_lock_script = CScript([OP_DUP, OP_HASH160, dsthash, OP_EQUALVERIFY, OP_CHECKSIG])
        if amount is None:
            amount = in_amount - fee
            return [COut(amount=amount, script=dst_lock_script)], 0, amount
        else:
            cashback = in_amount - amount - fee
            cashback_lock_script = CScript([OP_DUP, OP_HASH160, pubhash, OP_EQUALVERIFY, OP_CHECKSIG])
            return [COut(amount=cashback, script=cashback_lock_script), COut(amount=amount, script=dst_lock_script)], cashback, amount

    def make_transaction(self, dsthash, amount, feekb=MINIMAL_FEE, fee=0, confirmations=6):
        from hash import hash160
        from crypto import privkey2pubkey, pubkey2pubwif, sign_data
        from transaction import CTransaction
        pubkey = privkey2pubkey(self.privkey)
        pubwif = pubkey2pubwif(pubkey)
        pubhash = hash160(pubwif)
        unspent = self.get_unspent(confirmations=confirmations)
        vin, in_amount = self._make_vin(pubhash=pubhash, unspent=unspent)
        vout, _cashback, _amount = self._make_vout(pubhash=pubhash, dsthash=dsthash, in_amount=in_amount, amount=amount, fee=fee)
        _fee = fee
        tx = CTransaction(vin=vin, vout=vout)
        tx = tx.sign(privkey=self.privkey, pubwif=pubwif)
        while True:
            if fee == 0:
                txsize = len(tx.serialize())
                newfee = int(txsize * feekb / 1000)
                if _fee == newfee:
                    break;
            else:
                break
            _fee = newfee
            vout, _cashback, _amount = self._make_vout(pubhash=pubhash, dsthash=dsthash, in_amount=in_amount, amount=amount, fee=_fee)
            tx = CTransaction(vin=vin, vout=vout)
            tx = tx.sign(privkey=self.privkey, pubwif=pubwif)

        return tx, _cashback, _amount, _fee
