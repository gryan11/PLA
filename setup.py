from distutils.core import setup

setup(name='pla',
    version='0.1',
    packages=['pla'],
    install_requires=[
        'lz4',
        'psutil',
        'pandas',
        'tqdm',
        'filelock'
        # 'unqlite'
    ],
)

    # py_modules=['kconc_utils', 'pla'],
