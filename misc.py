#!/usr/bin/env python3

import ecdsa
import base58
import hashlib


PREFIX_ADDRESS = 0x00
PREFIX_PAY2SCRIPT = 0x05
PREFIX_TESNETADDR = 0x6F
PREFIX_PRIVKEY = 0x80
PREFIX_ENCPRIVKEY = 0x0142 # BIP-38
PREFIX_EXTPUBCEY = 0x0488B21E # BIP-32
"""
Clamping the lower bits ensures the key is a multiple of the cofactor. This is done to prevent small subgroup attacks.
Clamping the (second most) upper bit to one is done because certain implementations of the Montgomery Ladder don't correctly handle this bit being zero. I believe curve25519-donna is impacted.
a[0] &= 248; a[31] &= 127; a[31] |= 64;

>>> p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
>>> x = 55066263022277343669578718895168534326250603453777594175500187360389116729240
>>> y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
>>> (x ** 3 + 7) % p == y**2 % p
"""

def base58CheckEncode(prefix, payload):
    def countLeadingZeroes(s):
        count = 0
        for c in s:
            if c == '\0':
                count += 1
            else:
                break
        return count

    s = bytes([prefix]) + payload
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
    result = s + checksum
    return '1' * countLeadingZeroes(result) + str(base58.b58encode(result))

def base58CheckDecode(prefix, payload):
    def countLeadingOnes(s):
        count = 0
        for c in s:
            if c == '1':
                count += 1
            else:
                break
        return count

    nzeros = countLeadingOnes(payload)
    payload = payload[nzeros:]
    payload = base58.b58decode(payload)
    if prefix != payload[0]:
        raise Exception('payload prefix missmatch: except {}, got {}'.format(prefix, payload[0]))
    checksum = payload[-4:]
    payload = payload[:-4]
    calculated_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
    if checksum != calculated_checksum:
        raise Exception('ivalid checksum')
    payload = payload[1:] # remove prefix
    return b'\0' * nzeros + payload

def privkey2wif(key, compressed=False):
    if compressed:
        key += bytes([0x01]) # append 'compression' suffix. https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc#comp_priv
    return base58CheckEncode(0x80, key)

def wif2privkey(wif_key):
    privkey = base58CheckDecode(0x80, wif_key)
    if len(privkey) == 33 and privkey[-1] == 0x01:
        return (privkey[:-1], True) # remove 'compression' suffix. https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc#comp_priv
    return (privkey, False)

def privkey2pubkey(privkey):
    sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
    return sk.verifying_key.to_string()

def pubkey2wif(pubkey, compressed=True):
    if not compressed:
        return b'\x04' + pubkey
    x, y = pubkey[:32], pubkey[32:]
    prefix = b'\x02' if (y[-1] % 2) == 0 else b'\x03'
    return prefix + x

def pubkey2addr(pubkey):
    pubwif = pubkey2wif(pubkey, compressed=True)
    sha256 = hashlib.sha256(pubwif).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    return base58CheckEncode(0x00, ripemd160)

def key2addr(s):
    return pubkey2addr(privkey2pubkey(s))


privkeystr = b'KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ' # 1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy
privkey, compressed = wif2privkey(privkeystr)
print(privkey2wif(privkey, compressed))
#import binascii
#privkey = binascii.unhexlify('18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725') # 1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs
pubkey = privkey2pubkey(privkey)
print(pubkey.hex())
pubwif = pubkey2wif(pubkey)
print(pubwif.hex())
print(key2addr(privkey))
#print(privateKeyToWif(binascii.unhexlify('0a56184c7a383d8bcce0c78e6e7a4b4b161b2f80a126caa48bde823a4625521f')))
#print(base58.b58decode(privkeystr).hex())
