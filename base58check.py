def base58CheckEncode(payload):
    from base58 import b58encode
    from hash import sha256
    def countLeadingZeroes(s):
        count = 0
        for c in s:
            if c == '\0':
                count += 1
            else:
                break
        return count

    checksum = sha256(sha256(payload))[0:4]
    result = payload + checksum
    return b'1' * countLeadingZeroes(result) + b58encode(result)

def base58CheckDecode(payload):
    from base58 import b58decode
    from hash import sha256
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
    payload = b58decode(payload)
    checksum = payload[-4:]
    payload = b'\0' * nzeros + payload[:-4]
    calculated_checksum = sha256(sha256(payload))[:4]
    if checksum != calculated_checksum:
        raise Exception('ivalid checksum')
    return payload
