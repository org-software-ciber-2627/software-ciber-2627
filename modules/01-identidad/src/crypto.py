import os
import base64
from Crypto.Cipher import AES


def encrypt(plaintext: str, key: bytes) -> tuple[str, str, str]:
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return (
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(nonce).decode(),
        base64.b64encode(tag).decode(),
    )


def decrypt(ciphertext_b64: str, iv_b64: str, tag_b64: str, key: bytes) -> str:
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(iv_b64)
    tag = base64.b64decode(tag_b64)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")