import pytest

@pytest.mark.parametrize(
        'seed, privwif, address',
        [
            ('qwe', b'5JWqeLAMTwv5Lci8j3PgAvfTg4ysvADWzT9VcXsUkekozhfw14d', b'1As78U2NPZejfgaiENyfiiGmiRUqi7C6Am'),
            ('12345', b'5JeWp8SHj8QQMtEAy1wnMbYHwXxNFgJLXuaiWEPTGsbKrAxmMJN', b'1NxpWQVjsHp4Zbp3miM4A8MTXvNSTjuLfL'),
        ]
    )
def test(seed, privwif, address):
    from crypto import seed2privkey, privkey2wif, privkey2addr
    privkey = seed2privkey(seed)
    assert privkey2wif(privkey, compressed=False) == privwif
    assert privkey2addr(privkey) == address
