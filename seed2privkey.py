#!/usr/bin/env python3

while True:
    from getpass import getpass
    from misc import yesno
    from crypto import seed2privkey, privkey2addr, privkey2wif
    seed = getpass('seed: ')
    privkey = seed2privkey(seed)
    print('privkey: {}'.format(privkey2wif(privkey, False)))
    print('address: {}'.format(privkey2addr(privkey)))
    if yesno('exit?'):
        break
