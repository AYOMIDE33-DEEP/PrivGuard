# core/crypto_core.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Tuple, Optional, Dict, Any
import json
import os
import secrets
import struct
from datetime import datetime, timezone

from werkzeug.datastructures import FileStorage

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# ----------------------------
# File format
# ----------------------------
MAGIC = b"PGC1"               # PrivGuard Crypto v1
VERSION = 1                   # 1 byte
SALT_LEN = 16                 # scrypt salt
NONCE_LEN = 12                # AESGCM nonce
KEY_LEN = 32                  # AES-256
META_MAX = 32_768             # safety cap for metadata json

DEFAULT_OUT_DIR = Path(__file__).resolve().parents[1] / "vault"
DEFAULT_OUT_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class CryptoMeta:
    original_name: str
    label: str
    note: str
    created_utc: str

    def to_bytes(self) -> bytes:
        d = {
            "original_name": self.original_name,
            "label": self.label,
            "note": self.note,
            "created_utc": self.created_utc,
        }
        raw = json.dumps(d, ensure_ascii=False).encode("utf-8")
        if len(raw) > META_MAX:
            raise ValueError("Metadata too large.")
        return raw

    @staticmethod
    def from_bytes(b: bytes) -> "CryptoMeta":
        d = json.loads(b.decode("utf-8", errors="strict"))
        return CryptoMeta(
            original_name=str(d.get("original_name") or ""),
            label=str(d.get("label") or ""),
            note=str(d.get("note") or ""),
            created_utc=str(d.get("created_utc") or ""),
        )


def _scrypt_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")
    pw = password.encode("utf-8")
    kdf = Scrypt(
        salt=salt,
        length=KEY_LEN,
        n=2**15,
        r=8,
        p=1,
    )
    return kdf.derive(pw)


def _safe_filename(name: str) -> str:
    name = (name or "").replace("\\", "/").split("/")[-1].strip()
    return name or "file.bin"


def _random_enc_name() -> str:
    return f"{secrets.token_hex(8)}.enc"


def _build_plain(meta_json: bytes, file_bytes: bytes) -> bytes:
    return struct.pack(">I", len(meta_json)) + meta_json + file_bytes


def _parse_plain(plain: bytes) -> tuple[CryptoMeta, bytes]:
    if len(plain) < 4:
        raise ValueError("Corrupted payload.")
    (mlen,) = struct.unpack(">I", plain[:4])
    if mlen <= 0 or mlen > META_MAX:
        raise ValueError("Invalid metadata length.")
    if len(plain) < 4 + mlen:
        raise ValueError("Corrupted payload.")
    meta_raw = plain[4:4 + mlen]
    data = plain[4 + mlen:]
    meta = CryptoMeta.from_bytes(meta_raw)
    return meta, data


def _encode_blob(salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return MAGIC + bytes([VERSION]) + salt + nonce + ciphertext


def _decode_blob(blob: bytes) -> tuple[int, bytes, bytes, bytes]:
    if len(blob) < len(MAGIC) + 1 + SALT_LEN + NONCE_LEN + 16:
        raise ValueError("Invalid encrypted file.")
    if blob[:4] != MAGIC:
        raise ValueError("Not a PrivGuard encrypted file.")
    ver = blob[4]
    if ver != VERSION:
        raise ValueError(f"Unsupported version: {ver}")
    salt = blob[5:5 + SALT_LEN]
    nonce = blob[5 + SALT_LEN:5 + SALT_LEN + NONCE_LEN]
    ct = blob[5 + SALT_LEN + NONCE_LEN:]
    return ver, salt, nonce, ct


def _read_upload_bytes(uploaded: FileStorage) -> bytes:
    # Robust read even if stream pointer moved
    if uploaded is None:
        return b""
    try:
        if hasattr(uploaded, "stream") and hasattr(uploaded.stream, "seek"):
            try:
                uploaded.stream.seek(0)
            except Exception:
                pass
        return uploaded.read() or b""
    except Exception:
        # fallback: try stream directly
        try:
            if hasattr(uploaded, "stream"):
                try:
                    uploaded.stream.seek(0)
                except Exception:
                    pass
                return uploaded.stream.read() or b""
        except Exception:
            return b""


def encrypt_upload_to_file(
    uploaded: FileStorage,
    password: str,
    *,
    encrypt_names: bool = True,
    label: str = "",
    note: str = "",
    out_dir: Optional[Path] = None,
) -> Tuple[str, str]:
    """
    Encrypt uploaded file using AES-256-GCM.
    Returns (output_path, download_filename).
    - If encrypt_names=True, download_filename is random .enc (no name leakage).
    - Metadata is encrypted inside the file: original_name + label + note.
    """
    if uploaded is None or not getattr(uploaded, "filename", None):
        raise ValueError("No file uploaded.")
    if not password:
        raise ValueError("Password is required.")

    out_dir = out_dir or DEFAULT_OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    original_name = _safe_filename(uploaded.filename)
    file_bytes = _read_upload_bytes(uploaded)

    meta = CryptoMeta(
        original_name=original_name,
        label=(label or "").strip(),
        note=(note or "").strip(),
        created_utc=datetime.now(timezone.utc).isoformat(),
    )
    meta_json = meta.to_bytes()

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _scrypt_key(password, salt)

    aesgcm = AESGCM(key)
    plain = _build_plain(meta_json, file_bytes)
    ct = aesgcm.encrypt(nonce, plain, None)

    blob = _encode_blob(salt, nonce, ct)

    if encrypt_names:
        dl_name = _random_enc_name()
    else:
        stem = Path(original_name).name
        dl_name = f"encrypted_{stem}.enc"

    out_path = out_dir / dl_name
    out_path.write_bytes(blob)
    return str(out_path), dl_name


def decrypt_upload_to_file(
    uploaded: FileStorage,
    password: str,
    *,
    out_dir: Optional[Path] = None,
) -> Tuple[str, str]:
    """
    Decrypt uploaded encrypted file.
    Returns (output_path, download_filename) where download filename is original_name.
    """
    if uploaded is None or not getattr(uploaded, "filename", None):
        raise ValueError("No file uploaded.")
    if not password:
        raise ValueError("Password is required.")

    out_dir = out_dir or DEFAULT_OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    blob = _read_upload_bytes(uploaded)
    _, salt, nonce, ct = _decode_blob(blob)
    key = _scrypt_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plain = aesgcm.decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Wrong password or corrupted file.")

    meta, data = _parse_plain(plain)

    original_name = _safe_filename(meta.original_name) or "decrypted.bin"
    out_path = out_dir / original_name

    if out_path.exists():
        stem = out_path.stem
        suf = out_path.suffix
        out_path = out_dir / f"{stem}_restored{suf}"

    out_path.write_bytes(data)
    return str(out_path), out_path.name


def peek_encrypted_metadata(uploaded: FileStorage, password: str) -> Dict[str, Any]:
    """
    Lets UI show label/original name after user enters password,
    without writing decrypted file yet.
    """
    if uploaded is None or not getattr(uploaded, "filename", None):
        raise ValueError("No file uploaded.")
    if not password:
        raise ValueError("Password is required.")

    blob = _read_upload_bytes(uploaded)
    _, salt, nonce, ct = _decode_blob(blob)

    key = _scrypt_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plain = aesgcm.decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Wrong password or corrupted file.")

    meta, _ = _parse_plain(plain)
    return {
        "original_name": meta.original_name,
        "label": meta.label,
        "note": meta.note,
        "created_utc": meta.created_utc,
    }