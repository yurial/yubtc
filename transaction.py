def script2pkh(script):
    from script import OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG
    if (len(script) != 25
        or script[0] != OP_DUP
        or script[1] != OP_HASH160
        or script[2] != 20
        or script[-2] != OP_EQUALVERIFY
        or script[-1] != OP_CHECKSIG):
        raise Exception('invalid script')
    return script[3:-2]

def toVarInt(value):
    """Pack `value` into varint bytes"""
    from struct import pack
    buf = b''
    while True:
        towrite = value & 0x7f
        value >>= 7
        if value:
            buf += pack(b'B', towrite | 0x80)
        else:
            buf += pack(b'B', towrite)
            break
    return buf

class CIn(object):
    def __init__(self, txhash, n, script, sequence=0xffffffff):
        if len(txhash) != 32:
            raise Exception('txhash shoud be 32 bytes lenght')
        if n < 0:
            raise Exception('n should be greater than 0')
        if n > 0xffffffff:
            raise Exception('n should be less or equal than 0xffffffff')
        if sequence < 0:
            raise Exception('sequence should be greater than 0')
        if sequence > 0xffffffff:
            raise Exception('sequence should be less or equal than 0xffffffff')
        self.txhash = bytes(txhash)
        self.n = n
        self.script = script
        self.sequence = sequence

    def serialize(self):
        """
        32 bytes    Transaction Hash                Pointer to the transaction containing the UTXO to be spent
        4 bytes     Output Index                    The index number of the UTXO to be spent; first one is 0
        1–9 bytes   (VarInt) Unlocking-Script Size  Unlocking-Script length in bytes, to follow
        Variable    Unlocking-Script                A script that fulfills the conditions of the UTXO locking script
        4 bytes     Sequence Number                 Used for locktime or disabled (0xFFFFFFFF)
        """
        from struct import pack
        result = self.txhash
        result += pack(b"<L", self.n)
        result += toVarInt(len(self.script))
        result += self.script
        result += pack(b"<L", self.sequence)
        return result

class COut(object):
    def __init__(self, amount, script):
        if amount < 0:
            raise Exception('amount should be greater than 0')
        if amount > 0xffffffffffffffff:
            raise Exception('amount should be less or equal than 0xffffffffffffffff')
        self.amount = amount
        self.script = script

    def serialize(self):
        """
        8 bytes (little-endian) Amount
        1–9 bytes (VarInt) lock script size
        Locking-Script
        """
        from struct import pack
        result = pack(b"<Q", self.amount)
        result += toVarInt(len(self.script))
        result += self.script
        return result

class CTransaction(object):
    def __init__(self, vin, vout, locktime=0):
        self.version = 2
        self.vin = vin
        self.vout = vout
        self.locktime = locktime

    def serialize(self):
        from struct import pack
        result = pack(b"<L", self.version)
        result += toVarInt(len(self.vin))
        for i in self.vin:
            result += i.serialize()
        result += toVarInt(len(self.vout))
        for o in self.vout:
            result += o.serialize()
        result += pack(b"<L", self.locktime)
        return result

    def sign(self, privkey, pubwif):
        from copy import deepcopy
        from crypto import sign_data
        from script import CScript
        from struct import pack
        tx = deepcopy(self)
        SIGHASH_ALL = 0x01
        sigdata = tx.serialize() + pack(b'<L', SIGHASH_ALL)
        signature = sign_data(privkey=privkey, data=sigdata)+ pack(b'<B', SIGHASH_ALL)
        script = CScript([signature, pubwif])
        for i in range(len(tx.vin)):
            tx.vin[i].script = script
        return tx

    def id(self):
        from hash import sha256
        return sha256(sha256(self.serialize()))[::-1]
