# PGMMV_Decrypter

Pixel Game Maker MV Decrypter

## Install

```sh
# Standard Version
pip install git+https://github.com/blluv/pgmm_decrypt.git

# Fast Version
pip install git+https://github.com/wqhanginge/PGMMV_Decrypter.git@fast
```

## Usage

```py
from pgmmvdec import decrypt_key, decrypt_resource_bytes, decrypt_resource_file


# signature

decrypt_key(encrypted_key: bytes | bytearray) -> bytes
decrypt_resource_bytes(file_bytes: bytes | bytearray, key: bytes | bytearray) -> bytes
decrypt_resource_file(file: str, out: str, key: bytes | bytearray) -> int


# decrypt key (in info.json)

with open('info.json', 'r', encoding='utf-8') as f:
    import base64, json
    encrypted_key = base64.b64decode(json.load(f)['key'])
decrypted_key = decrypt_key(encrypted_key)


# decrypt resource

with open('encrypted_resource_file', 'rb') as encf, open('decrypted_resource_file', 'wb') as decf:
    file_bytes = encf.read()
    decrypted_bytes = decrypt_resource_bytes(file_bytes, decrypted_key)
    decf.write(decrypted_bytes)

decrypt_resource_file('encrypted_resource_file', 'decrypted_resource_file', decrypted_key)
```

## Command Line Script

```sh
pgmmvdec [-o OUTPUT] [-q] [-k KEY | -x KEY] input

# decrypt one resource file with the key detected from directory
pgmmvdec encrypted.png -o decrypted.png

# decrypt resource directory with a custom key
pgmmvdec -k "Resource Key" ./Resources/img/

# retrieve the key without resource decryption
pgmmvdec -q ./Resources/
```

## Twofish
Source code from [twofish](https://packages.debian.org/source/buster/twofish).
