from hashlib import sha256
from secrets import token_bytes

from pgmmvdec._minicrypto import CBC, CBCDecIter, CBCEncIter, Identity

BLOCK_COUNT = 16
BLOCK_SIZE = 16


def test_Identity():
    cipher = Identity()
    data = tuple(token_bytes(BLOCK_SIZE) for _ in range(BLOCK_COUNT))

    for block in data:
        assert cipher.decrypt(block) == cipher.encrypt(block) == block,\
            'Identity: Incorrect cipher process'
    print('Identity: Passed')


def test_CBC():
    cipher, cbc = Identity(), CBC(token_bytes(BLOCK_SIZE))

    data = b''.join(token_bytes(BLOCK_SIZE) for _ in range(BLOCK_COUNT))
    output = cbc.decrypt(cipher, cbc.encrypt(cipher, data))

    assert output == data, 'CBC: Incorrect encrypted/decrypted data'
    print('CBC: Passed')


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

    assert outhash.digest() == inhash.digest(), 'CBCIter: Incorrect encrypted/decrypted data'
    print('CBCIter: Passed')


if __name__ == '__main__':
    test_Identity()
    test_CBC()
    test_CBCIter()
