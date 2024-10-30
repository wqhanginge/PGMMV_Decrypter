from io import BufferedReader
from typing import Generator

from ._minicrypto import xor_bytes


def derive_subkey(key: bytes, plaintext_len: int) -> bytes:
    if len(key) < 8:    # make sure `key` is long enough
        key += b'\0' * (8 - len(key))

    ptl_bytes = plaintext_len.to_bytes(8, 'little').rstrip(b'\0')   # 8 bytes for length value should be enough
    xor_key = xor_bytes(ptl_bytes, key).replace(b'\0', b'\1')       # this stops at the end of the shorter one

    return xor_key + key[len(xor_key):] # append the rest unchanged bytes, `key` is alwalys longer


def make_iter(inbytes: bytes | BufferedReader, block_size: int = 16) -> Generator[bytes, None, None]:
    if isinstance(inbytes, bytes):
        for offset in range(0, len(inbytes), block_size):
            yield inbytes[offset : offset + block_size]

    elif isinstance(inbytes, BufferedReader):
        yield from iter(lambda: inbytes.read(block_size), b'')

    else:
        raise TypeError(f'Invalid inbytes type: {type(inbytes)}')
