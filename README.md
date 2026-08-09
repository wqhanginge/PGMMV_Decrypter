# PGMMV_Decrypter

Pixel Game Maker MV Decrypter

A fast version of tool [**pgmm_decrypt**](https://github.com/blluv/pgmm_decrypt), delivering approximately 10x speedup and featuring a convenient command-line interface.

## Install

Grab the latest packaged release and install directly.

If you prefer or need to compile from source, use pip with the GitHub repo:

```sh
pip install git+https://github.com/wqhanginge/PGMMV_Decrypter.git
```

## Usage

```py
from pgmmvdec import decrypt_key, decrypt_resource_bytes, decrypt_resource_file


# signature

decrypt_key(encrypted_key: bytes) -> bytes
decrypt_resource_bytes(resource_bytes: bytes, padding_len: int, key: bytes) -> bytes
decrypt_resource_file(file: str, out: str, key: bytes) -> int


# decrypt key (in info.json)

with open('info.json', 'r', encoding='utf-8') as f:
    import base64, json
    encrypted_key = base64.b64decode(json.load(f)['key'])
decrypted_key = decrypt_key(encrypted_key)


# decrypt resource (notice the metadata)

with open('encrypted_resource_file', 'rb') as encf, open('decrypted_resource_file', 'wb') as decf:
    file_bytes = encf.read()
    decrypted_bytes = decrypt_resource_bytes(file_bytes[4:], file_bytes[3], decrypted_key)
    decf.write(decrypted_bytes)

decrypt_resource_file('encrypted_resource_file', 'decrypted_resource_file', decrypted_key)
```

## Command-Line Interface

```sh
pgmmvdec [-o OUTPUT] [-y] [-e | -k KEY | -x KEY] INPUT

# decrypt one resource file with the key detected from directory
pgmmvdec encrypted.png -o decrypted.png

# decrypt resource directory with a custom key
pgmmvdec -k "Resource Key" ./Resources/img/

# retrieve the key from a specific file
pgmmvdec -e ./sample.json
```

## Thanks

This work is based on [**pgmm_decrypt**](https://github.com/blluv/pgmm_decrypt) by **blluv**.

**Twofish** source code can be found at debian packages [website](https://www.debian.org/distrib/packages).
