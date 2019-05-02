#!/usr/bin/env python3

from crypto import *

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
