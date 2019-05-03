if str != bytes:
    raw_input = input

def yesno(question):
    while True:
        choice = raw_input(question).lower()
        if choice[:1] == 'y':
            return True
        elif choice[:1] == 'n':
            return False
        else:
            print("Please respond with 'Yes' or 'No'\n")


def get_unspent(address):
    import requests
    url = 'https://blockchain.info/unspent?active={address}'.format(address=address)
    return requests.get(url).json()['unspent_outputs']
