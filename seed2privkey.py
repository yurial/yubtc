#!/usr/bin/env python3

while True:
    from getpass import getpass
    from misc import yesno
    from crypto import seed2privkey, privkey2addr, privkey2privwif
    seed = getpass('seed: ')
    privkey = seed2privkey(seed)
    print('uncompressed privkey: {}'.format(privkey2privwif(privkey, compressed=False)))
    print('uncompressed address: {}'.format(privkey2addr(privkey, compressed=False)))
    print('compressed privkey: {}'.format(privkey2privwif(privkey, compressed=True)))
    print('compressed address: {}'.format(privkey2addr(privkey, compressed=True)))
    if yesno('exit? '):
        break
