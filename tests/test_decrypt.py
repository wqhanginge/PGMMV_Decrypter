from pgmmvdec.decrypt import derive_subkey, xor_bytes

SAMPLES = (
    {
        'key': bytes.fromhex('0123456789ABCDEFFEDCBA9876543210'),
        'int': 1,
        'sub': bytes.fromhex('0123456789ABCDEFFEDCBA9876543210'),
    },
    {
        'key': bytes.fromhex('0F1E2D3C4B5A69788796A5B4C3D2E1F0'),
        'int': 2147483647,
        'sub': bytes.fromhex('F0E1D2434B5A69788796A5B4C3D2E1F0'),
    },
)


def test_xor_bytes():
    for sample in SAMPLES:
        assert xor_bytes(sample['key'], sample['key']).strip(b'\0') == b'',\
            f'{xor_bytes.__name__}: Incorrect output of "{sample["key"].hex()}"'
        print(f'{xor_bytes.__name__}: Sample "{sample["key"].hex()}" passed')


def test_derive_subkey():
    for sample in SAMPLES:
        assert derive_subkey(sample['key'], sample['int']) == sample['sub'],\
            f'{derive_subkey.__name__}: Incorrect subkey of "{sample["key"].hex()}"'
        print(f'{derive_subkey.__name__}: Sample "{sample["key"].hex()}" passed')


if __name__ == '__main__':
    test_xor_bytes()
    test_derive_subkey()
