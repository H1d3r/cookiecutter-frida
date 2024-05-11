from Crypto.Cipher import AES
import hashlib
import base64
from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes


def AESEncrypt(src: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    raw = cipher.encrypt(pad(src, AES.block_size, style="pkcs7"))
    return raw


def AESDecrypt(enc: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = unpad(cipher.decrypt(enc), AES.block_size, style="pkcs7")
    return dec


def AESTest():
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    src = b"secret"
    enc = AESEncrypt(src, key, iv)
    print(AESDecrypt(enc, key, iv))


if __name__ == "__main__":
    AESTest()
