import pytest

@pytest.mark.parametrize(
        'compressed, seed, privwif, address',
        [
            (False, 'qwe', b'5JWqeLAMTwv5Lci8j3PgAvfTg4ysvADWzT9VcXsUkekozhfw14d', b'1NVVsaqV5QEVQiCA8xYCoJkz6jpHuC9hfK'),
            (True, 'qwe', b'KzJhhmaHKwPG9acZ6ZZ5torkjSa3jdgFNaQVHqFoVfeNRPUtx1mQ', b'1As78U2NPZejfgaiENyfiiGmiRUqi7C6Am'),
            (False, '12345', b'5JeWp8SHj8QQMtEAy1wnMbYHwXxNFgJLXuaiWEPTGsbKrAxmMJN', b'1Q3DSdXMUkdHBtJNbNaQELWYsgtYWhtfU3'),
            (True, '12345', b'Kztab1pcpwgJ7B78zFAoBuT7mhdNonTXDR5pC266y4JWBwKrxwgc', b'1NxpWQVjsHp4Zbp3miM4A8MTXvNSTjuLfL'),
        ]
    )
def test(compressed, seed, privwif, address):
    from crypto import seed2privkey, privkey2privwif, privkey2addr
    privkey = seed2privkey(seed)
    assert privkey2privwif(privkey, compressed) == privwif
    assert privkey2addr(privkey, compressed) == address
