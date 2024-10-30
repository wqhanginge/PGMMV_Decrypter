'''Minimal set of cryptographic algorithms for PGMMV.'''

from typing import Iterable, Self

def xor_bytes(bytes1: bytes, bytes2: bytes, *, strict: bool = False) -> bytes:
    '''
    Perform an XOR operation on two byte lists.

    :param bytes bytes1:
    :param bytes bytes2:
    :param bool strict: Raise a ValueError if the length of the byte sequence are not equal.
    '''
    ...


# Block ciphers

class Cipher():
    '''Abstract base class for a block cipher.'''

    def encrypt(self, block: bytes) -> bytes:
        '''Encrypt a 16-byte block of plaintext.'''
        ...

    def decrypt(self, block: bytes) -> bytes:
        '''Decrypt a 16-byte block of ciphertext.'''
        ...

class Identity(Cipher):
    '''Identity block mapping.'''

    def __init__(self) -> None: ...
    def encrypt(self, block: bytes) -> bytes: ...
    def decrypt(self, block: bytes) -> bytes: ...

class Twofish(Cipher):
    '''Twofish block cipher algorithm with a key length within [0, 32] bytes.'''

    def __init__(self, key: bytes) -> None: ...
    def encrypt(self, block: bytes) -> bytes: ...
    def decrypt(self, block: bytes) -> bytes: ...
    def key(self) -> bytes: ...

class Weakfish(Cipher):
    '''PGMMV special key schedule algorithm.'''

    def __init__(self) -> None: ...
    def encrypt(self, block: bytes) -> bytes: ...
    def decrypt(self, block: bytes) -> bytes: ...


# Iterators for block cipher modes of operation
# Iterates one block at a time until the input is exhausted

class CipherIter():
    '''Abstract base iterator for a block cipher mode.'''

    def __iter__(self) -> Self: ...
    def __next__(self) -> bytes: ...

class CBCEncIter(CipherIter):
    '''Cipher Block Chaining iterator with a 16-byte IV.'''

    def __init__(self, cipher: Cipher, iv: bytes, input_iterable: Iterable[bytes]) -> None: ...
    def __iter__(self) -> Self: ...
    def __next__(self) -> bytes: ...

class CBCDecIter(CipherIter):
    '''Cipher Block Chaining iterator with a 16-byte IV.'''

    def __init__(self, cipher: Cipher, iv: bytes, input_iterable: Iterable[bytes]) -> None: ...
    def __iter__(self) -> Self: ...
    def __next__(self) -> bytes: ...


# Block cipher modes of operation
# Stores the state of the block cipher mode and processes the entire data at once

class CipherMode():
    '''Abstract base class for a block cipher mode.'''

    def encrypt(self, cipher: Cipher, data: bytes) -> bytes: ...
    def decrypt(self, cipher: Cipher, data: bytes) -> bytes: ...

class CBC(CipherMode):
    '''Cipher Block Chaining with a 16-byte IV.'''

    def __init__(self, iv: bytes) -> None: ...
    def encrypt(self, cipher: Cipher, data: bytes) -> bytes: ...
    def decrypt(self, cipher: Cipher, data: bytes) -> bytes: ...
    def iv(self) -> bytes: ...
