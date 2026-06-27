# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for MediaRelay Windows executable."""

import os

block_cipher = None

_src_root = os.path.abspath("src")
_entry_script = os.path.abspath(os.path.join("scripts", "pyinstaller_entry.py"))

a = Analysis(
    [_entry_script],
    pathex=[_src_root],
    binaries=[],
    datas=[],
    hiddenimports=[
        "mediarelay",
        "mediarelay.server",
        "mediarelay.auth",
        "mediarelay.routes",
        "mediarelay.error_handlers",
        "mediarelay.config",
        "mediarelay.constants",
        "mediarelay.handlers",
        "mediarelay.lockout",
        "mediarelay.logging_config",
        "mediarelay.path_utils",
        "mediarelay.templates",
        "mediarelay.generate_password",
        "mediarelay.session_store",
        "mediarelay.subtitle_sanitize",
        "flask",
        "werkzeug",
        "waitress",
        "flask_limiter",
        "limits",
        "click",
        "dotenv",
        "colorlog",
        "psutil",
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
    name="MediaRelay",
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
)
