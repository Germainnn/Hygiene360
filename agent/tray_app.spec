# -*- mode: python ; coding: utf-8 -*-
import sys
import os
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

a = Analysis(
    ['tray_launcher.py'],  # entry point
    pathex=['.'],  # or absolute path if needed
    binaries=[],
    datas=[
        ('modules', 'modules'),  # include modules directory
        ('Hygiene360.ico', 'agent'),   # include icon
        ('icons', 'icons')
    ],
    hiddenimports=[
        'flask',
        'pystray',
        'PIL.Image',
        'win32com.client',
        *collect_submodules('agent.modules')  # includes os_patch, antivirus, etc.
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Hygiene360Agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # tray app should be silent
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='Hygiene_360.ico'
)
