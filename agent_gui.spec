# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['agent/gui.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('agent/modules', 'modules'), 
        ('agent/Hygiene_360.ico', 'agent'),
    ],
    hiddenimports=[
        'flask',
        'win32com.client',
        'agent.modules.os_patch',
        'agent.modules.antivirus',
        'agent.modules.firewall',
        'agent.modules.software',
        'agent.modules.security_tools'
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
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='agent/Hygiene_360.ico'
)