import pytest

@pytest.mark.parametrize(
        'compressed, seed, privhex, privwif, address',
        [
            (False, 'qwe', '1814825e69d2e72eabfbec9c0168f5689dcc26509aa2a8590d859a90402f0495', b'5Hztg9Lf6fPida3GtdxhzmC6gTh98oQ6dGPotiFWMBSauUioQxj', b'1HXSiiE8wqH7rtqXW3duSWLBjm4v8XZNX8'),
            (True, 'qwe', '1814825e69d2e72eabfbec9c0168f5689dcc26509aa2a8590d859a90402f0495', b'Kx2X5mom9zTGkQq38v8swx3z5ApAuRnwq4wfyF52Y55veC7Ce5dz', b'1A3XHZzcxp3bC62T21DQhXZuA6GdzVYxP9'),
            (False, '12345', '28820488de48082a13c570e68e1295e0207c6ef826a685c220d10fd6d8b95d49', b'5J88JQkRPEffAwVL73kwtDzGFqtBFiCsFXajzb9ytmCZbs4VSUY', b'1MN1fFX2xmKS1qZXyhw5EUpS9Laa2HaeYX'),
            (True, '12345', '28820488de48082a13c570e68e1295e0207c6ef826a685c220d10fd6d8b95d49', b'KxaTDqped9KdUsW3KhAyF6KkLWktFvsNo7yvmBke7U62tWmMs8dk', b'1sW6JDNWppzUjQr8jjQ9KJmVx92ooKEd6'),
        ]
    )
def test(compressed, seed, privhex, privwif, address):
    from crypto import seed2privkey, privkey2privwif, privkey2addr
    privkey = seed2privkey(seed)
    assert privkey.hex() == privhex
    assert privkey2privwif(privkey, compressed) == privwif
    assert privkey2addr(privkey, compressed) == address

"""
this test included in main test()
def test_bin2privkey():
    import axolotl_curve25519 as curve
    from crypto import seed2privkey, seed2bin
    seed = 'my test seed'
    assert seed2privkey(seed) == curve.generatePrivateKey(seed2bin(seed))
"""
