from distutils.core import setup

setup(name='pla',
    version='0.1',
    py_modules=['kconc_utils', 'pla'],
    install_requires=[
        'lz4',
        'psutil',
        'pandas',
        'tqdm',
        'filelock'
        # 'unqlite'
    ],
)

