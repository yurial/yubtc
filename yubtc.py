#!/usr/bin/env python3
import click

from fwd import MINIMAL_FEE, DEFAULT_CONFIRMATIONS
from fwd import TSatoshi, TBTC, TAmount
from wallet import Wallet, MINIMAL_FEE
from seed import generate_seed, get_seed

@click.group()
def cli():
    pass

@cli.command('newseed', help='Generate new seed.')
@click.option('-n', help='Count of words (default=15).', default=15, required=False, nargs=1, type=int)
@click.option('-u', '--unique', help='Only unique words is seed.', default=False, required=False, is_flag=True)
def newseed(n: int, unique: bool):
    seed = generate_seed(count=n, allow_dups=not unique)
    wallet = Wallet(seed=seed)
    print('{seed}\r\nAddress: {address}'.format(seed=seed, address=wallet.adresses[0].get_p2pkh_address().decode('ascii')))

@cli.command('address', help='Show native (P2PKH) address and exit.')
@click.option('-n', '--nonce', help='Scan adresses from given nonce', default=0, required=False, nargs=1, type=int)
def address(nonce: int):
    wallet = Wallet(seed=get_seed(), nonce=nonce)
    print(wallet.adresses[0].get_p2pkh_address().decode('ascii'))

@cli.command('dumpprivkey', help='Show private key in WIF format and exit.')
@click.option('-n', '--nonce', help='Scan adresses from given nonce', default=0, required=False, nargs=1, type=int)
def dumpprivkey(nonce: int):
    wallet = Wallet(seed=get_seed(), nonce=nonce)
    print('Address: {address}'.format(address=wallet.adresses[0].get_p2pkh_address().decode('ascii')))
    print(wallet.get_privwif().decode('ascii'))

@cli.command('balance', help='Show balance and exit.')
@click.option('-n', '--nonce', help='Scan adresses from given nonce', default=0, required=False, nargs=1, type=int)
@click.option('-c', '--confirmations', help='Minimal confirmations for inputs.', default=6, required=False, nargs=1, type=int)
@click.option('--new', help='Count of new unused addresses', default=1, required=False, nargs=1, type=int)
@click.option('-v', '--verbose', help='Print verbosity', default=False, required=False, is_flag=True)
def balance(nonce: int, confirmations: int, new: int, verbose: bool):
    from misc import satoshi2btc
    total = 0
    wallet = Wallet(seed=get_seed(), nonce=nonce, new_addresses=new)
    for privkey in wallet.privkeys:
        txs = privkey.get_unspent(confirmations=confirmations)
        in_amount = 0
        for tx in txs:
            in_amount += tx['amount']
        address = privkey.get_p2pkh_address().decode('ascii')
        amount: TBTC = satoshi2btc(in_amount)
        total += amount
        print(f'{privkey.nonce}# {address}: {amount:0.08f} BTC')
        if verbose:
            for tx in txs:
                tx_id = tx['tx']
                tx_out_n = tx['out_n']
                vin = f'({tx_id}:{tx_out_n})'
                amount = satoshi2btc(tx['amount'])
                print(f'    {vin}: {amount}')
    print(f'Total: {total:0.08f}')

@cli.command('send', help='Send BTC to address. ADDRESS - Destination address. Only P2PKH or P2SH addresses supported. AMOUNT - value to send in decimal. Set "ALL" to send all available funds.')
@click.option('-n', '--nonce', help='Scan adresses from given nonce', default=0, required=False, nargs=1, type=int)
@click.option('-c', '--confirmations', help='Minimal confirmations for inputs.', default=6, required=False, nargs=1, type=int)
@click.option('-f', '--fee', help='Set transaction fee. Value in decimal.', default=TBTC(0), required=False, nargs=1, type=TBTC)
@click.option('-k', '--feekb', help='Set fee per kilobyte (1000 bytes). Value in satoshi.', default=MINIMAL_FEE, required=False, nargs=1, type=int)
@click.option('--send', help='Send transaction to network, just print to console.', default=False, is_flag=True)
@click.argument('address', type=str)
@click.argument('amount', type=str)
def send(nonce:int , confirmations: int, fee: TBTC, feekb: TSatoshi, address: str, amount: TAmount, send: bool):
    amount = None if amount == 'ALL' else TBTC(amount)
    wallet = Wallet(seed=get_seed(), nonce=nonce)
    print('Address: {address}'.format(address=wallet.privkeys[0].get_p2pkh_address().decode('ascii')))
    wallet.send(dst=address, amount=amount, fee=fee, feekb=feekb, confirmations=confirmations, send=send)

if __name__ == '__main__':
    cli()
