'''Minimal set of cryptographic algorithms for PGMMV.'''

from typing import Iterable, Self

def xor_bytes(bytes1: bytes | bytearray, bytes2: bytes | bytearray, *, strict: bool = False) -> bytes:
    '''
    Perform an XOR operation on two byte lists.

    :param bytes-like bytes1:
    :param bytes-like bytes2:
    :param bool strict: Raise a ValueError if the lengths of the two byte lists are not equal.
    '''
    ...


# Block ciphers

class Cipher():
    '''Abstract base class for a block cipher.'''

    def encrypt(self, block: bytes | bytearray) -> bytes:
        '''Encrypt a 16-byte block of plaintext.'''
        ...

    def decrypt(self, block: bytes | bytearray) -> bytes:
        '''Decrypt a 16-byte block of ciphertext.'''
        ...

class Twofish(Cipher):
    '''Twofish block cipher algorithm with a key length within [0, 32] bytes.'''

    def __init__(self, key: bytes | bytearray) -> None: ...
    def encrypt(self, block: bytes | bytearray) -> bytes: ...
    def decrypt(self, block: bytes | bytearray) -> bytes: ...
    def key(self) -> bytes: ...

class Weakfish(Cipher):
    '''PGMMV special key schedule algorithm.'''

    def __init__(self) -> None: ...
    def encrypt(self, block: bytes | bytearray) -> bytes: ...
    def decrypt(self, block: bytes | bytearray) -> bytes: ...


# Iterators for block cipher modes of operation
# Iterates one block at a time until the input is exhausted

class CipherIter():
    '''Abstract base iterator for a block cipher mode.'''

    def __iter__(self) -> Self: ...
    def __next__(self) -> bytes: ...

class CBCIter(CipherIter):
    '''Cipher Block Chaining iterator with a 16-byte IV.'''

    def __init__(self, cipher: Cipher, iv: bytes | bytearray, input_iter: Iterable[bytes | bytearray], *, is_decrypt: bool) -> None: ...
    def __iter__(self) -> Self: ...
    def __next__(self) -> bytes: ...


# Block cipher modes of operation
# Stores the state of the block cipher mode and processes the entire data at once

class CipherMode():
    '''Abstract base class for a block cipher mode.'''

    def encrypt(self, cipher: Cipher, data: bytes | bytearray) -> bytes: ...
    def decrypt(self, cipher: Cipher, data: bytes | bytearray) -> bytes: ...

class CBC(CipherMode):
    '''Cipher Block Chaining with a 16-byte IV.'''

    def __init__(self, iv: bytes | bytearray) -> None: ...
    def encrypt(self, cipher: Cipher, data: bytes | bytearray) -> bytes: ...
    def decrypt(self, cipher: Cipher, data: bytes | bytearray) -> bytes: ...
    def iv(self) -> bytes: ...
