from hashlib import sha256
from pathlib import Path

from pgmmvdec.pgmmv import decrypt_key, decrypt_resource_bytes, decrypt_resource_file

KEY = b'PGMMV TEST KEY\0\0'
SAMPLE_ROOT = Path(__file__).parent / 'samples'
SAMPLES = (
    {
        'type': 'string',
        'name': 'string.txt',
        'sha256': '9cd620fef71c14851f76e0862234e8e4f5a8fc6c344572bcd2407482e5ce07b8',
    },
    {
        'type': 'image',
        'name': 'image.png',
        'sha256': '406ae51c00e06048cfb465af44020c0cba18e351fa937d13c0bfd9dd56c64aa6',
    },
)


def test_decrypt_key():
    from base64 import b64decode
    from json import loads

    raw_key = loads(Path(SAMPLE_ROOT / 'info.json').read_bytes())['key']
    key = decrypt_key(b64decode(raw_key))

    assert key == KEY, f'{decrypt_key.__name__}: Incorrect decrypted key'
    print(f'{decrypt_key.__name__}: Passed')


def test_decrypt_resource_bytes():
    for sample in SAMPLES:
        fbytes = decrypt_resource_bytes(Path(SAMPLE_ROOT / sample['name']).read_bytes(), KEY)

        assert sha256(fbytes).hexdigest() == sample['sha256'],\
            f'{decrypt_resource_bytes.__name__}: Incorrect decrypted {sample["type"]}'
        print(f'{decrypt_resource_bytes.__name__}: Sample {sample["type"]} passed')


def test_decrypt_resource_file():
    from os import remove
    TMP = 'decrypted.tmp'

    for sample in SAMPLES:
        decrypt_resource_file(SAMPLE_ROOT / sample['name'], SAMPLE_ROOT / TMP, KEY)

        assert sha256(Path(SAMPLE_ROOT / TMP).read_bytes()).hexdigest() == sample['sha256'],\
            f'{decrypt_resource_file.__name__}: Incorrect decrypted {sample["type"]}'
        print(f'{decrypt_resource_file.__name__}: Sample {sample["type"]} passed')

    remove(SAMPLE_ROOT / TMP)


if __name__ == '__main__':
    test_decrypt_key()
    test_decrypt_resource_bytes()
    test_decrypt_resource_file()
