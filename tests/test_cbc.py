from hashlib import sha256
from secrets import token_bytes

from pgmmvdec._minicrypto import CBC, CBCDecIter, CBCEncIter, Identity

BLOCK_COUNT = 16
BLOCK_SIZE = 16


def test_CBC():
    cipher, cbc = Identity(), CBC(token_bytes(BLOCK_SIZE))

    data = b''.join(token_bytes(BLOCK_SIZE) for _ in range(BLOCK_COUNT))
    output = cbc.decrypt(cipher, cbc.encrypt(cipher, data))

    assert data == output, f'{CBC.__name__}: Incorrect encrypted/decrypted data'
    print(f'{CBC.__name__}: Passed')


def test_CBCIter():
    cipher, iv = Identity(), token_bytes(BLOCK_SIZE)

    def data_iter(hash):
        for _ in range(BLOCK_COUNT):
            block = token_bytes(BLOCK_SIZE)
            hash.update(block)
            yield block

    inhash, outhash = sha256(), sha256()
    for block in CBCDecIter(cipher, iv, CBCEncIter(cipher, iv, data_iter(inhash))):
        outhash.update(block)

    assert inhash.digest() == outhash.digest(),\
        f'{CBCEncIter.__name__}/{CBCDecIter.__name__}: Incorrect encrypted/decrypted data'
    print(f'{CBCEncIter.__name__}/{CBCDecIter.__name__}: Passed')


if __name__ == '__main__':
    test_CBC()
    test_CBCIter()
