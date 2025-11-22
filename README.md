# PGMMV_Decrypter

Pixel Game Maker MV Decrypter

A fast version of tool [**pgmm_decrypt**](https://github.com/blluv/pgmm_decrypt), delivering approximately 10x speedup and featuring a convenient command-line interface.

## Install

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
pgmmvdec [-o OUTPUT] [-q] [-f] [-k KEY | -x KEY] input

# decrypt one resource file with the key detected from directory
pgmmvdec encrypted.png -o decrypted.png

# decrypt resource directory with a custom key
pgmmvdec -k "Resource Key" ./Resources/img/

# retrieve the key without resource decryption
pgmmvdec -q ./Resources/
```

## Thanks

This work is based on [**pgmm_decrypt**](https://github.com/blluv/pgmm_decrypt) by **blluv**.

**Twofish** source code from [debian packages](https://packages.debian.org/source/buster/twofish).
