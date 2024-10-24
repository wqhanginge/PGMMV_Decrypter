from ._minicrypto import CBC, CBCIter, Twofish, Weakfish
from .decrypt import derive_subkey, make_iter

PGMMV_IV = bytes.fromhex("A047E93D230A4C62A744B1A4EE857FBA")


def _is_weak(key: bytes | bytearray) -> bool:
    return len(key) <= 8


def decrypt_key(encrypted_key: bytes | bytearray) -> bytes:
    # The key for encrypted_key is "key". However, since it's too short (3 bytes),
    # we decrypt it using weakfish.
    return CBC(PGMMV_IV).decrypt(Weakfish(), encrypted_key)


def decrypt_resource_bytes(file_bytes: bytes | bytearray, key: bytes | bytearray) -> bytes:
    if file_bytes[:3] != b'enc':    # resource file is not encrypted
        return file_bytes

    pt_len = len(file_bytes) - 4 - file_bytes[3]
    cipher = Weakfish() if _is_weak(key) else Twofish(derive_subkey(key, pt_len))
    pt_iter = CBCIter(cipher, PGMMV_IV, make_iter(file_bytes[4:]), is_decrypt=True)

    return (b''.join(pt_iter))[:pt_len]


def decrypt_resource_file(file: str, out: str, key: bytes | bytearray) -> int:
    from os import SEEK_END, SEEK_SET
    with open(file, 'rb') as ifp, open(out, 'wb') as ofp:
        # `peek` is not guaranteed to return the requested size of bytes,
        # but requesting only 4 bytes should be ok
        meta = ifp.peek(4)

        if meta[:3] != b'enc':   #resource file is not encrypted
            pt_len = None
            pt_iter = make_iter(ifp)
        else:
            pt_len = ifp.seek(0, SEEK_END) - ifp.seek(4, SEEK_SET) - meta[3]
            cipher = Weakfish() if _is_weak(key) else Twofish(derive_subkey(key, pt_len))
            pt_iter = CBCIter(cipher, PGMMV_IV, make_iter(ifp), is_decrypt=True)

        for block in pt_iter: ofp.write(block)
        return ofp.truncate(pt_len)
