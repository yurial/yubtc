SUFFIX_PRIVKEY_COMPRESSED = 0x01
PREFIX_ADDRESS = 0x00
PREFIX_PUBKEY_EVEN = 0x02
PREFIX_PUBKEY_ODD = 0x03
PREFIX_PUBKEY_FULL = 0x04
PREFIX_PAY2SCRIPT = 0x05
PREFIX_TESNETADDR = 0x6F
PREFIX_PRIVKEY = 0x80
PREFIX_ENCPRIVKEY = 0x0142 # BIP-38
PREFIX_EXTPUBCEY = 0x0488B21E # BIP-32

def seed2privkey(seed, nonce=0):
    from struct import pack
    data = pack(">L", nonce) + str2bytes(seed)
    privkey = sha256(keccak256(blake256(data)))
    """
    Clamping the lower bits ensures the key is a multiple of the cofactor. This is done to prevent small subgroup attacks.
    Clamping the (second most) upper bit to one is done because certain implementations of the Montgomery Ladder don't correctly handle this bit being zero. I believe curve25519-donna is impacted.
    """
    privkey[0] &= 248
    privkey[31] &= 127
    privkey[31] += 64
    return privkey

def privkey2wif(key, compressed=False):
    from base58check import base58CheckEncode
    if compressed:
        key += bytes([SUFFIX_PRIVKEY_COMPRESSED]) # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc#comp_priv
    return base58CheckEncode(PREFIX_PRIVKEY, key)

def wif2privkey(wif_key):
    from base58check import base58CheckDecode
    privkey = base58CheckDecode(PREFIX_PRIVKEY, wif_key)
    if len(privkey) == 33 and privkey[-1] == SUFFIX_PRIVKEY_COMPRESSED:
        return (privkey[:-1], True) # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc#comp_priv
    return (privkey, False)

def privkey2pubkey(privkey):
    import ecdsa
    sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
    return sk.verifying_key.to_string()

def pubkey2wif(pubkey, compressed=True):
    if not compressed:
        return bytes([PREFIX_PUBKEY_FULL]) + pubkey
    x, y = pubkey[:32], pubkey[32:]
    prefix = PREFIX_PUBKEY_EVEN if (y[-1] % 2) == 0 else PREFIX_PUBKEY_ODD
    return bytes([prefix]) + x

def pubkey2addr(pubkey):
    from base58check import base58CheckEncode
    from hash import sha256, ripemd160
    pubwif = pubkey2wif(pubkey, compressed=True)
    hash = ripemd160(sha256(pubwif))
    return base58CheckEncode(PREFIX_ADDRESS, hash)

def key2addr(s):
    return pubkey2addr(privkey2pubkey(s))

"""
>>> p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
>>> x = 55066263022277343669578718895168534326250603453777594175500187360389116729240
>>> y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
>>> (x ** 3 + 7) % p == y**2 % p
"""
