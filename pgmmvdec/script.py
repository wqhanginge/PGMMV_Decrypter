from argparse import ArgumentParser
from pathlib import Path

from . import decrypt_key, decrypt_resource_file

PGMMV_INFO_PATHS = (
    Path('info.json'),
    Path('data', 'info.json'),
)
PGMMV_KEY_DICTKEY = 'key'
DECRYPTED_SUFFIX = '_dec'


parser = ArgumentParser(description='Pixel Game Maker MV Decrypter')
parser.add_argument('input', type=Path, help='PGMMV resource file or directory')
parser.add_argument('-o', '--out', metavar='OUTPUT', type=Path, help='specify the output file or directory')
parser.add_argument('-q', '--query', action='store_true', help='query the key and exit without decryption')
parser.add_argument('-f', '--force', action='store_true', help='overwrite existing files without prompt')
exgroup = parser.add_mutually_exclusive_group()
exgroup.add_argument('-k', '--key', metavar='KEY', help='specify the key in str type')
exgroup.add_argument('-x', '--hex', metavar='KEY', help='specify the key in hex type')


def find_key(cwd: Path) -> bytes | None:
    from base64 import b64decode
    from json import loads

    while cwd != cwd.parent:
        pths = tuple(cwd/pth for pth in PGMMV_INFO_PATHS if (cwd/pth).exists())
        if pths:
            enckey = b64decode(loads(pths[0].read_text('utf-8'))[PGMMV_KEY_DICTKEY])
            return decrypt_key(enckey)
        cwd = cwd.parent
    return None


def prompt_overwrite(file: Path) -> bool:
    return input(f'File {file} already exists\nOverwrite(y/N)? ').strip().lower() == 'y'


def decrypt_iter_path(src: Path, dst: Path, key: bytes, force: bool = False) -> None:
    from collections import deque

    tasks = deque(((src, dst),))
    while tasks:
        srcp, dstp = tasks.popleft()
        if srcp.is_file():
            if (not dstp.exists() or force or prompt_overwrite(dstp)):
                print(f'  {srcp.name if srcp == src else srcp.relative_to(src)}')
                decrypt_resource_file(srcp, dstp, key)
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
    else:
        cwd = args.input.parent if args.input.is_file() else args.input
        key = find_key(cwd)
    key = key.rstrip(b'\0') if key is not None else None

    if args.query:
        ans = f'Resource key: {key.hex()} "{key.decode("utf-8", "backslashreplace")}"'\
            if key is not None else 'No Resource key found'
        print(ans)
        return

    if key is None:
        raise RuntimeError('Cannot find the resource key')
    print(f'Decrypting resources to {args.out}')
    decrypt_iter_path(args.input, args.out, key, args.force)
    print('Done')


if __name__ == '__main__':
    main()
