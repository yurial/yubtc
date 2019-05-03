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

    def get_address(self, compressed=None):
        from crypto import privkey2addr
        return privkey2addr(privkey=self.privkey, compressed=self.get_compressed(compressed))

    def get_unspent(self):
        from misc import get_unspent
        return get_unspent(self.get_address())
