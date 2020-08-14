magic = 0xd9b4bef9

def makeMessage(magic, command, payload):
    """
    4   magic       uint32_t    Magic value indicating message origin network, and used to seek to next message when stream state is unknown
    12  command     char[12]    ASCII string identifying the packet content, NULL padded (non-NULL padding results in packet rejected)
    4   length      uint32_t    Length of payload in number of bytes
    4   checksum    uint32_t    First 4 bytes of sha256(sha256(payload))
    ?   payload     uchar[]     The actual data
"""
    from struct import pack
    from hash import sha256
    checksum = sha256(sha256(payload))[0:4]
    return pack('<L12sL4s', magic, command, len(payload), checksum) + payload

def netaddr(services, ipaddr, port):
    """
    4   time        uint32      The Time (version >= 31402). Not present in version message.
    8   services    uint64_t    Same service(s) listed in version
    16  IPv6/4      char[16]    IPv6 address. Network byte order. The original client only supported IPv4 and only read the last 4 bytes to get the IPv4 address.
                                However, the IPv4 address is written into the message as a 16 byte IPv4-mapped IPv6 address
    2   port        uint16_t    Port number, network byte order
    """
    from struct import pack
    v4_prefix = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff'
    return pack('<Q', services) + v4_prefix + pack('>4sH', ipaddr, port)

def makeTxMsg(rawtxdata):
  return makeMessage(magic, b'tx', rawtxdata)

def makeVersionMsg():
    """
    4   version         int32_t     Identifies protocol version being used by the node
    8   services        uint64_t    bitfield of features to be enabled for this connection
    8   timestamp       int64_t     standard UNIX timestamp in seconds
    26  addr_recv       net_addr    The network address of the node receiving this message
    Fields below require version ≥ 106
    26  addr_from       net_addr    The network address of the node emitting this message
    8   nonce           uint64_t    Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self.
    ?   user_agent      var_str     User Agent (0x00 if string is 0 bytes long)
    4   start_height    int32_t     The last block received by the emitting node
    Fields below require version ≥ 70001
    1   relay   bool    Whether the remote peer should announce relayed transactions or not, see BIP 0037
    """
    from time import time
    from struct import pack
    from socket import inet_aton 
    from random import getrandbits
    from misc import varstr
    version = 60002
    services = 1
    timestamp = int(time())
    addr_me = netaddr(services, inet_aton("127.0.0.1"), 8333)
    addr_you = netaddr(services, inet_aton("127.0.0.1"), 8333)
    nonce = getrandbits(64)
    user_agent = varstr(b'yubtc')
    start_height = 0

    payload = pack('<lQq26s26sQ', version, services, timestamp, addr_me, addr_you, nonce) + user_agent + pack('<l', start_height)
    return makeMessage(magic, b'version', payload)

def sendTx(rawtxdata):
    from time import sleep
    from socket import create_connection, getaddrinfo, socket
    host = "seed.bitcoinstats.com"
    service = 8333
    print('connect to {}'.format(host))
    sock = create_connection((host, service))
    print('send version')
    sock.send(makeVersionMsg())
    print('recv version')
    sleep(0.1)  # TODO: read all bytes of answer
    sock.recv(1000) # receive version and verack
    print('send transaction to network')
    sock.send(makeTxMsg(rawtxdata))
    sock.close()
    print('done')
