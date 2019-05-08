
def keccak256(data):
    from sha3 import keccak_256
    return keccak_256(data).digest()

def sha256(data):
    from hashlib import sha256
    return sha256(data).digest()

def ripemd160(data):
    import hashlib
    return hashlib.new('ripemd160', data).digest()

def blake256(data):
    from pyblake2 import blake2b
    return blake2b(data, digest_size=32).digest()

def hash160(data):
    return ripemd160(sha256(data))
