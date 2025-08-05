from fwd import TSatoshi, TBTC, TAmount

if str != bytes:
    raw_input = input

# Returns byte string value, not hex string
def varint(n):
    from struct import pack
    if n < 0xfd:
        return pack('<B', n)
    elif n < 0xffff:
        return pack('<cH', '\xfd', n)
    elif n < 0xffffffff:
        return pack('<cL', '\xfe', n)
    else:
        return pack('<cQ', '\xff', n)

# Takes and returns byte string value, not hex string
def varstr(s):
    return varint(len(s)) + s

def yesno(question):
    while True:
        choice = raw_input(question).lower()
        if choice[:1] == 'y':
            return True
        elif choice[:1] == 'n':
            return False
        else:
            print("Please respond with 'Yes' or 'No'\n")

def satoshi2btc(satoshi: TSatoshi) -> TBTC:
    return TBTC(satoshi) * TBTC((0, (1,), -8))

def btc2satoshi(btc: TBTC) -> TSatoshi:
    return TSatoshi(btc * TBTC((0, (1,), 8)))

def get_address_unspent(address):
    import requests
    from json.decoder import JSONDecodeError
    address = address.decode('ascii')
    try:
        url = 'https://blockchain.info/unspent?active={address}'.format(address=address)
        return requests.get(url).json()['unspent_outputs']
    except JSONDecodeError:
        return []
    raise Exception('Unknown error')

def get_address_info(address):
    import requests
    from json.decoder import JSONDecodeError
    address = address.decode('ascii')
    try:
        url = 'https://blockchain.info/balance?active={address}'.format(address=address)
        response = requests.get(url)
        return response.json()[address]
    except JSONDecodeError:
        return {'total_received': 0}
    raise Exception('Unknown error')
