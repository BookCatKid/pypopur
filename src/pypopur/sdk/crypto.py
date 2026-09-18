"""Crypto primitives used by the SDK wire formats.

Ports of (all under smali_classes3/com/thingclips/smart/android/common/utils/):
- ``AESUtil`` — ``Cipher.getInstance("AES")`` = AES/ECB/PKCS5Padding, keyed by a
  ``SecretKeySpec`` over the raw localKey bytes. ``encrypt`` emits UPPERCASE
  hex (``byte2hex`` calls ``toUpperCase``); ``encryptWithBase64`` emits base64;
  ``encryptWithBytes`` emits raw ciphertext.
- ``AesGcmUtil`` — AES/GCM/NoPadding, 12-byte nonce, 128-bit tag; the
  ``*AppendNonce*`` variants prepend the nonce to the ciphertext.
- ``MD5.md5`` — UPPERCASE hex digest (callers lowercase when they need it).
- ``CRC32Utils.crc32`` — table CRC32 == zlib.crc32.
- Thing ``Base64`` — commons-codec semantics: unchunked standard alphabet,
  lenient decode that skips non-alphabet bytes.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import zlib

from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_GCM_NONCE_LENGTH = 12
_GCM_TAG_BITS = 128


def md5_upper(value: str) -> str:
    """``MD5.md5``: uppercase hex digest of the default-charset bytes."""

    return hashlib.md5(value.encode(), usedforsecurity=False).hexdigest().upper()


def crc32(data: bytes) -> int:
    """``CRC32Utils.crc32``: returns a Java ``int`` (signed interpretation of
    the CRC); bit pattern identical to ``zlib.crc32``."""

    return zlib.crc32(data) - (1 << 32) if zlib.crc32(data) > 0x7FFFFFFF else zlib.crc32(data)


def base64_encode(data: bytes | None) -> bytes | None:
    """Thing ``Base64.encodeBase64`` (commons-codec): unchunked standard base64.
    ``None`` in → ``None`` out (Java NPE avoided by faithful callers)."""

    if data is None:
        return None
    return base64.b64encode(data)


def base64_decode(data: bytes | str | None) -> bytes:
    """commons-codec ``Base64.decodeBase64`` / ``android.util.Base64.decode``
    (flags=0): lenient — non-alphabet bytes are skipped rather than rejected."""

    if data is None:
        return b""
    if isinstance(data, str):
        data = data.encode()
    # Java decoders ignore characters outside the base64 alphabet; only '=' is
    # significant as padding. Filter then decode.
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    filtered = bytes(b for b in data if b in alphabet)
    # Pad to a multiple of 4 so lenient streams decode.
    filtered += b"=" * (-len(filtered) % 4)
    try:
        return base64.b64decode(filtered)
    except (ValueError, TypeError):
        # Truncated/corrupt tail — decode what is valid, mirroring the Java
        # decoder's best-effort behavior.
        usable = filtered[: len(filtered) - (len(filtered) % 4)]
        usable = usable.rstrip(b"=")
        usable += b"=" * (-len(usable) % 4)
        return base64.b64decode(usable)


def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES/ECB/PKCS5Padding encrypt (``AESUtil`` core)."""

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """AES/ECB/PKCS5Padding decrypt; raises on bad padding like doFinal does."""

    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def hex2byte(value: str | None) -> bytes | None:
    """``AESUtil.hex2byte``: null/odd-length → None; pairs via
    ``Integer.parseInt(pair, 16)`` — ValueError propagates like Java's
    NumberFormatException does into the caller's catch."""

    if value is None or len(value) % 2 == 1:
        return None
    return bytes(int(value[index : index + 2], 16) for index in range(0, len(value), 2))


class AESUtil:
    """Port of ``AESUtil`` with ALGO fixed to ``"AES"`` (ECB/PKCS5Padding)."""

    def __init__(self, key: bytes) -> None:
        self._key = key

    def encrypt(self, plaintext: str) -> str:
        """``encrypt(String)``: ciphertext as UPPERCASE hex (``byte2hex``)."""

        return aes_ecb_encrypt(self._key, plaintext.encode()).hex().upper()

    def encrypt_with_base64(self, plaintext: str) -> str:
        """``encryptWithBase64(String)``: ciphertext base64 string."""

        return base64_encode(aes_ecb_encrypt(self._key, plaintext.encode())).decode()

    def encrypt_with_bytes(self, plaintext: str | bytes) -> bytes:
        """``encryptWithBytes``: raw ciphertext bytes."""

        data = plaintext.encode() if isinstance(plaintext, str) else bytes(plaintext)
        return aes_ecb_encrypt(self._key, data)

    def decrypt(self, hex_ciphertext: str) -> str:
        """``decrypt(String)``: hex input → default-charset string out."""

        return aes_ecb_decrypt(self._key, hex2byte(hex_ciphertext)).decode(errors="replace")

    def decrypt_bytes(self, ciphertext: bytes) -> str:
        """``decrypt(byte[])``: UTF-8 string out."""

        return aes_ecb_decrypt(self._key, ciphertext).decode("utf-8", errors="replace")

    def decrypt_with_base64(self, b64_ciphertext: str) -> str:
        """``decryptWithBase64(String)``: b64 input → default-charset string."""

        return aes_ecb_decrypt(self._key, base64_decode(b64_ciphertext.encode())).decode(
            errors="replace"
        )

    def decrypt_with_bytes(self, ciphertext: bytes) -> bytes:
        """``decryptWithBytes(byte[])``: raw plaintext bytes."""

        return aes_ecb_decrypt(self._key, ciphertext)


def gcm_encrypt_appended_nonce(
    key: bytes, plaintext: bytes, aad: bytes | None, *, nonce: bytes | None = None
) -> bytes:
    """``AesGcmUtil.encryptBytes2BytesAppendNonce``: 12-byte random nonce
    prepended to ``ct || 128-bit tag``."""

    if nonce is None:
        nonce = secrets.token_bytes(_GCM_NONCE_LENGTH)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def gcm_decrypt_appended_nonce(key: bytes, data: bytes, aad: bytes | None) -> bytes:
    """``AesGcmUtil.decryptBytesAppendedNonce2Bytes``: nonce at [0:12]."""

    nonce, ciphertext = data[:_GCM_NONCE_LENGTH], data[_GCM_NONCE_LENGTH:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
