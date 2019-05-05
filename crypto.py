SUFFIX_PRIVKEY_COMPRESSED = 0x01
PREFIX_ADDRESS = 0x00
PREFIX_PUBKEY_EVEN = 0x02
PREFIX_PUBKEY_ODD = 0x03
PREFIX_PUBKEY_FULL = 0x04
PREFIX_P2SH = 0x05 # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch07.asciidoc#pay-to-script-hash-p2sh
PREFIX_TESNETADDR = 0x6F
PREFIX_PRIVKEY = 0x80
PREFIX_ENCPRIVKEY = 0x0142 # BIP-38
PREFIX_EXTPUBKEY = 0x0488B21E # BIP-32
# TODO: SEGWIT https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch07.asciidoc#segregated-witness

if bytes == str:  # python2
    str2bytes = lambda s: s
    bytes2str = lambda b: b
    str2list = lambda s: [ord(c) for c in s]
else:  # python3
    str2bytes = lambda s: s.encode('latin-1')
    bytes2str = lambda b: ''.join(map(chr, b))
    str2list = lambda s: [c for c in s]

def seed2bin(seed, nonce=0):
    from hash import sha256, keccak256, blake256
    from struct import pack
    data = pack(">L", nonce) + str2bytes(seed)
    return sha256(keccak256(blake256(data)))

def bin2privkey(data, nonce=0):
    privkey = bytearray(data)
    """
    Clamping the lower bits ensures the key is a multiple of the cofactor. This is done to prevent small subgroup attacks.
    Clamping the (second most) upper bit to one is done because certain implementations of the Montgomery Ladder don't correctly handle this bit being zero.
    """
    privkey[0] &= 248
    privkey[31] &= 127
    privkey[31] += 64
    return bytes(privkey)

def seed2privkey(seed, nonce=0):
    return bin2privkey(seed2bin(seed, nonce))

def privkey2privwif(privkey, compressed=True):
    from base58check import base58CheckEncode
    if compressed:
        privkey += bytes([SUFFIX_PRIVKEY_COMPRESSED]) # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc#comp_priv
    return base58CheckEncode(bytes([PREFIX_PRIVKEY]) + privkey)

def privwif2privkey(privwif):
    from base58check import base58CheckDecode
    privkey = base58CheckDecode(privwif)
    if privkey[0] != PREFIX_PRIVKEY:
        raise Exception('prefix missmatch')
    else:
        privkey = privkey[1:]
    if len(privkey) == 33 and privkey[-1] == SUFFIX_PRIVKEY_COMPRESSED:
        return (privkey[:-1], True) # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc#comp_priv
    return (privkey, False)

def privkey2pubkey(privkey):
    import ecdsa
    sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
    return sk.verifying_key.to_string()

def pubkey2pubwif(pubkey, compressed=True):
    if not compressed:
        return bytes([PREFIX_PUBKEY_FULL]) + pubkey
    x, y = pubkey[:32], pubkey[32:]
    prefix = PREFIX_PUBKEY_EVEN if (y[-1] % 2) == 0 else PREFIX_PUBKEY_ODD
    return bytes([prefix]) + x

def pubkey2addr(pubkey, compressed=True):
    from base58check import base58CheckEncode
    from hash import sha256, ripemd160
    pubwif = pubkey2pubwif(pubkey, compressed)
    hash = ripemd160(sha256(pubwif))
    return base58CheckEncode(bytes([PREFIX_ADDRESS]) + hash)

def privkey2addr(privkey, compressed=True):
    return pubkey2addr(privkey2pubkey(privkey), compressed)

"""
>>> p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
>>> x = 55066263022277343669578718895168534326250603453777594175500187360389116729240
>>> y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
>>> (x ** 3 + 7) % p == y**2 % p
"""
