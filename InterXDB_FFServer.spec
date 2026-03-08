# InterXDB_FFServer.spec
# PyInstaller build spec for InterXDB_FFServer v1.0
# Build: pyinstaller InterXDB_FFServer.spec --clean

import os
from PyInstaller.utils.hooks import collect_submodules

APP_DIR = os.path.abspath(os.path.dirname(SPEC))
SDK_DIR = os.path.join(APP_DIR, "TC_B_SDK_V64_20250611", "SDK FILES")

a = Analysis(
    [os.path.join(APP_DIR, 'interxdb.py')],
    pathex=[APP_DIR],
    binaries=[
        # Bundle the Anviz SDK DLL and its VC++ runtime dependencies
        (os.path.join(SDK_DIR, 'tc-b_new_sdk.dll'),  '.'),
        (os.path.join(SDK_DIR, 'msvcp120.dll'),       '.'),
        (os.path.join(SDK_DIR, 'msvcr120.dll'),       '.'),
    ],
    datas=[
        (os.path.join(APP_DIR, 'InterXDB LOGO.jpg'), '.'),  # GUI sidebar logo
        (os.path.join(APP_DIR, 'InterXICO.ico'),     '.'),  # window/taskbar icon
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,          # use COLLECT (folder mode, not one-file)
    name='InterXDB_FFServer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                      # UPX can corrupt native DLLs — keep off
    console=False,                  # no console window (GUI app)
    icon=os.path.join(APP_DIR, 'InterXICO.ico'),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='InterXDB_FFServer',
)
