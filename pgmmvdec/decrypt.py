from io import BufferedReader
from typing import Generator

from ._minicrypto import xor_bytes


def derive_subkey(key: bytes | bytearray, plaintext_len: int) -> bytes:
    if len(key) < 8:    # make sure `key` is long enough
        key += b'\0' * (8 - len(key))

    ptl_bytes = plaintext_len.to_bytes(8, 'little').rstrip(b'\0')   # 8 bytes for length value should be enough
    xor_key = xor_bytes(ptl_bytes, key).replace(b'\0', b'\1')       # this stops at the end of the shorter one

    return xor_key + key[len(xor_key):] # append the rest unchanged bytes, `key` is alwalys longer


def make_iter(inbytes: bytes | bytearray | BufferedReader, block_size: int = 16) -> Generator[bytes | bytearray, None, None]:
    if isinstance(inbytes, (bytes, bytearray)):
        for offset in range(0, len(inbytes), block_size):
            yield inbytes[offset : offset + block_size]

    elif isinstance(inbytes, BufferedReader):
        for block in iter(lambda: inbytes.read(block_size), b''):
            yield block

    else:
        raise TypeError(f'invalid inbytes type: {type(inbytes)}')
