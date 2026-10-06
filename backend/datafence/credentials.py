"""Windows current-user DPAPI storage; environment keys remain portable.

No secret is returned through health, model reports, or browser endpoints.
"""

import ctypes
from ctypes import wintypes
import os
from pathlib import Path


def _protect(data: bytes, decrypt: bool = False) -> bytes:
    if os.name != "nt":
        raise OSError("DPAPI credentials require Windows; use SENSENOVA_API_KEY elsewhere")

    class Blob(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_byte))]

    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    destination = Blob()
    function = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    function.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                         ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    function.restype = wintypes.BOOL
    if not function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(destination)):
        raise OSError("Current-user credential encryption/decryption failed")
    try:
        return ctypes.string_at(destination.data, destination.size)
    finally:
        kernel.LocalFree(destination.data)


def save_key(directory: Path, key: str) -> None:
    if not key.startswith("sk-") or len(key) > 512 or any(c.isspace() for c in key):
        raise ValueError("API key format is invalid")
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "sensenova.dpapi").write_bytes(_protect(key.encode("utf-8")))


def read_key(directory: Path) -> str | None:
    path = directory / "sensenova.dpapi"
    if not path.exists():
        return os.environ.get("SENSENOVA_API_KEY", "").strip() or None
    if path.stat().st_size > 8192:
        raise ValueError("Credential file exceeds size limit")
    return _protect(path.read_bytes(), decrypt=True).decode("utf-8")
