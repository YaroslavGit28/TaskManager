# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['task_manager.py'],
    pathex=[],
    binaries=[('ProcessMonitor.dll', '.')],
    datas=[],
    hiddenimports=['win32event', 'win32api', 'winerror'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='task_manager',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    collect_all=True,
    collect_submodules=True,
    collect_data_files=True,
    collect_binaries=True,
    bundle_files=1,
    onefile=True
)
