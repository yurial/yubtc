#!/usr/bin/env python3
import click
from decimal import Decimal
from wallet import Wallet
from seed import generate_seed, get_seed

@click.group()
def cli():
    pass

@cli.command('newseed', help='Generate new seed.')
@click.option('-n', help='Count of words (default=15).', default=15, required=False, nargs=1, type=int)
@click.option('-u', '--unique', help='Only unique words is seed.', default=False, required=False, is_flag=True)
def newseed(n, unique):
    seed = generate_seed(count=n, allow_dups=not unique)
    wallet = Wallet(seed=seed)
    print('{seed}\r\nAddress: {address}'.format(seed=seed, address=wallet.get_p2pkh_address().decode('ascii')))

@cli.command('address', help='Show native (P2PKH) address and exit.')
def address():
    wallet = Wallet(seed=get_seed())
    print(wallet.get_p2pkh_address().decode('ascii'))

@cli.command('dumpprivkey', help='Show private key in WIF format and exit.')
def dumpprivkey():
    wallet = Wallet(seed=get_seed())
    print('Address: {address}'.format(address=wallet.get_p2pkh_address().decode('ascii')))
    print(wallet.get_privwif().decode('ascii'))

@cli.command('balance', help='Show balance and exit.')
@click.option('-c', '--confirmations', help='Minimal confirmations for inputs.', default=6, required=False, nargs=1, type=int)
def balance(confirmations):
    wallet = Wallet(seed=get_seed())
    print('{address}: {amount:0.08f} BTC'.format(address=wallet.get_p2pkh_address().decode('ascii'), amount=wallet.get_balance(confirmations=confirmations)))
    pass

@cli.command('send', help='Send BTC to address. ADDRESS - Destination address. Only native P2PKH addresses supported. AMOUNT - value to send in decimal. Set "ALL" to send all available funds.')
@click.option('-c', '--confirmations', help='Minimal confirmations for inputs.', default=6, required=False, nargs=1, type=int)
@click.option('-f', '--fee', help='Set transaction fee. Value in decimal.', default=Decimal(0), required=False, nargs=1, type=Decimal)
@click.option('-k', '--feekb', help='Set fee per kilobyte (1000 bytes). Value in satoshi.', default=1000, required=False, nargs=1, type=int)
@click.argument('address', type=str)
@click.argument('amount', type=str)
def send(confirmations, fee, feekb, address, amount):
    amount = None if amount == 'ALL' else Decimal(amount)
    wallet = Wallet(seed=get_seed())
    print('Address: {address}'.format(address=wallet.get_p2pkh_address().decode('ascii')))
    wallet.send(dst=address, amount=amount, fee=fee, feekb=feekb, confirmations=confirmations)

if __name__ == '__main__':
    cli()
