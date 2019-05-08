magic = 0xd9b4bef9

def netaddr(ipaddr, port):
    from struct import pack
    services = 1
    return (pack('<Q12s', services, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff') + pack('>4sH', ipaddr, port))

def makeMessage(magic, command, payload):
    from struct import pack
    from hash import sha256
    checksum = sha256(sha256(payload))[0:4]
    return pack('<L12sL4s', magic, command, len(payload), checksum) + payload

def makeTxMsg(rawtxdata):
  return makeMessage(magic, b'tx', rawtxdata)

def makeVersionMsg():
    from time import time
    from struct import pack
    from socket import inet_aton 
    from random import getrandbits
    from misc import varstr
    version = 60002
    services = 1
    timestamp = int(time())
    addr_me = netaddr(inet_aton("127.0.0.1"), 8333)
    addr_you = netaddr(inet_aton("127.0.0.1"), 8333)
    nonce = getrandbits(64)
    sub_version_num = varstr(b'yubtc')
    start_height = 0

    payload = pack('<LQQ26s26sQsL', version, services, timestamp, addr_me, addr_you, nonce, sub_version_num, start_height)
    return makeMessage(magic, b'version', payload)

def sendTx(rawtxdata):
    from socket import create_connection, getaddrinfo, socket, AF_UNSPEC, SOCK_STREAM
    host = "seed.bitcoinstats.com"
    service = 8333
    sock = create_connection((host, service))
    sock.send(makeVersionMsg())
    sock.recv(1000) # receive version
    sock.recv(1000) # receive verack
    sock.send(makeTxMsg(rawtxdata))
