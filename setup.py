from setuptools import Extension, setup, find_packages

src__minicrypto = 'pgmmvdec/_minicrypto/'
ext__minicrypto = Extension(
    name='pgmmvdec._minicrypto',
    sources=[
        src__minicrypto + 'minicrypto.c',
        src__minicrypto + 'cipher.c',
        src__minicrypto + 'cipher_iter.c',
        src__minicrypto + 'cipher_mode.c',
        src__minicrypto + '_C/fatal.c',
        src__minicrypto + '_C/twofish.c',
        src__minicrypto + '_C/weakfish.c',
    ],
    include_dirs=[src__minicrypto, src__minicrypto + '_C/'],
)

setup(
    name='pgmmvdec',
    version='0.1.0',
    description='Pixel Game Maker MV Decrypter',
    author='blluv and Gee Wang',
    packages=find_packages(),
    ext_modules=[ext__minicrypto],
    entry_points={'console_scripts': ['pgmmvdec = pgmmvdec.script:main']},
    license='MIT',
    python_requires='>=3.7',
)
