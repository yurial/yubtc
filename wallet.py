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

    def get_native_address(self, compressed=None):
        from crypto import privkey2addr
        return privkey2addr(privkey=self.privkey, compressed=self.get_compressed(compressed))

    def get_unspent(self, confirmations=6):
        from misc import get_unspent
        result = list()
        for x in get_unspent(self.get_native_address()):
            if x['confirmations'] >= confirmations:
                result.append({'tx': x['tx_hash'], 'out_n': x['tx_output_n'], 'value': x['value']})
        return result

    def send(self, address, amount, feekb=MINIMAL_FEE, fee=None):
        from base58check import base58CheckDecode
        pubkey = base58CheckDecode(address)
        print(pubkey)

    def send2native(self, address, amount, feekb=MINIMAL_FEE, fee=None):
        # DUP HASH160 PUSHDATA(20)[b278af2a89b9768a7964e934c608e56d7024fd70] EQUALVERIFY CHECKSIG
        pass
