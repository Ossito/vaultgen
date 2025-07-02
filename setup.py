from setuptools import setup

APP = ['vaultgen.py']
DATA_FILES = []
OPTIONS = {
    'argv_emulation': True,
    'iconfile': 'logo.icns',
    'plist': {
        'CFBundleName': "VaultGen",
        'CFBundleDisplayName': "VaultGen",
        'CFBundleVersion': "1.0.0",
    }
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)