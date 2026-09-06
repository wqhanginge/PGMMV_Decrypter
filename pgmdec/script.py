from argparse import ArgumentParser
from pathlib import Path

from . import decrypt_key, decrypt_resource_file

PGMMV_RES_ROOT = 'Resources'
PGMMV_INFO_ROOT = 'data'
PGMMV_INFO_FILE = 'info.json'
PGMMV_KEY_DICTKEY = 'key'
DECRYPTED_SUFFIX = '_dec'


parser = ArgumentParser(prog='pgmdec', description='Pixel Game Maker MV Decrypter')
parser.add_argument('input', metavar='INPUT', type=Path, help='resource file or directory')
parser.add_argument('-o', '--out', metavar='OUTPUT', type=Path, help='specify the output file or directory')
parser.add_argument('-y', '--force', action='store_true', help='overwrite existing files without prompt')
exgroup = parser.add_mutually_exclusive_group()
exgroup.add_argument('-e', '--extract', action='store_true', help='extract the key and exit')
exgroup.add_argument('-k', '--key', metavar='KEY', help='specify the key in str type')
exgroup.add_argument('-x', '--hex', metavar='KEY', help='specify the key in hex type')


def extract_key(file: Path) -> bytes | None:
    from base64 import b64decode
    from json import loads

    try:
        enckey = b64decode(loads(file.read_text('utf-8'))[PGMMV_KEY_DICTKEY])
        return decrypt_key(enckey)
    except:
        return None


def search_keyfile(root: Path) -> Path:
    fp = Path(PGMMV_INFO_FILE)

    if Path(root, PGMMV_INFO_FILE).exists():
        fp = root / PGMMV_INFO_FILE
    elif Path(root.parent, PGMMV_INFO_ROOT, PGMMV_INFO_FILE).exists():
        fp = root.parent / PGMMV_INFO_ROOT / PGMMV_INFO_FILE
    elif Path(root, PGMMV_INFO_ROOT, PGMMV_INFO_FILE).exists():
        fp = root / PGMMV_INFO_ROOT / PGMMV_INFO_FILE
    elif Path(root, PGMMV_RES_ROOT, PGMMV_INFO_ROOT, PGMMV_INFO_FILE).exists():
        fp = root / PGMMV_RES_ROOT / PGMMV_INFO_ROOT / PGMMV_INFO_FILE
    elif PGMMV_RES_ROOT in root.parts:
        idx = root.parts.index(PGMMV_RES_ROOT) + 1
        fp = Path(*root.parts[:idx], PGMMV_INFO_ROOT, PGMMV_INFO_FILE)

    return fp


def prompt_overwrite(): # -> Callable[[str], bool]
    prompt_str = 'File already exists: {fp}\nOverwrite? (y/a/N) '
    skip = False

    def prompt(file: str) -> bool:
        nonlocal skip
        opt = 'a' if skip else input(prompt_str.format(fp=file)).strip().lower()
        skip = opt == 'a'
        return skip or opt == 'y'

    return prompt


def decrypt_iter_path(src: Path, dst: Path, key: bytes, force: bool = False) -> None:
    from collections import deque

    prompt = prompt_overwrite()
    tasks = deque([(src, dst)])
    while tasks:
        srcp, dstp = tasks.popleft()
        if srcp.is_file():
            if (not dstp.exists() or force or prompt(dstp.name)):
                print(f'  {srcp.name}')
                decrypt_resource_file(srcp, dstp, key)  # type: ignore
        else:
            dstp.mkdir(parents=True, exist_ok=True)
            tasks.extend((pth, dstp/pth.name) for pth in srcp.iterdir())


def main() -> None:
    args = parser.parse_args()

    args.input = args.input.resolve()
    if not args.input.exists():
        raise ValueError(f'Path not found: {args.input}')
    elif args.input.samefile(args.input.parent):
        raise ValueError(f'Cannot use the root directory as input: {args.input}')

    args.out = args.input.with_stem(args.input.stem + DECRYPTED_SUFFIX) if args.out is None\
        else args.out.resolve()
    if args.input.is_file() and args.out == args.input:
        raise ValueError(f'Output cannot be the same as input: {args.out}')
    elif args.input.is_dir() and (args.out.is_relative_to(args.input) or args.input.is_relative_to(args.out)):
        raise ValueError(f'Output and input directories overlap: {args.out}, {args.input}')

    if args.key is not None:
        key = bytes(args.key, encoding='utf-8')
    elif args.hex is not None:
        key = bytes.fromhex(args.hex)
    elif args.extract:
        key = extract_key(args.input) if args.input.is_file() else extract_key(search_keyfile(args.input))
    else:
        cwd = args.input.parent if args.input.is_file() else args.input
        key = extract_key(search_keyfile(cwd))

    if key is None:
        print('No Resource key found')
    else:
        key = key.rstrip(b'\0')
        print(f'Resource key: {key.hex()} "{key.decode("utf-8", "backslashreplace")}"')

    if args.extract:
        return
    elif key is None:
        raise RuntimeError('Unable to extract the resource key')

    print(f'Decrypting resources to {args.out}')
    decrypt_iter_path(args.input, args.out, key, args.force)
    print('Done')


if __name__ == '__main__':
    main()
