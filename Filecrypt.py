"""Basic file encrypter: AES-256-GCM with a scrypt-derived key.
 
Usage:
    python filecrypt.py encrypt secret.txt        -> secret.txt.enc
    python filecrypt.py decrypt secret.txt.enc    -> secret.txt
 
Requires: pip install cryptography
"""
import argparse
import os
import sys
from getpass import getpass
 
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
 
MAGIC = b"FCRYPT1"   # file header, also bound into the auth tag
SALT_LEN = 16
NONCE_LEN = 12
EXT = ".enc"
 
 
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(password.encode())
 
 
def encrypt_file(path: str, password: str) -> str:
    with open(path, "rb") as f:
        plaintext = f.read()
 
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, MAGIC)
 
    out_path = path + EXT
    with open(out_path, "wb") as f:
        f.write(MAGIC + salt + nonce + ciphertext)
    return out_path
 
 
def decrypt_file(path: str, password: str) -> str:
    with open(path, "rb") as f:
        data = f.read()
 
    if not data.startswith(MAGIC):
        raise ValueError("Not a file produced by this tool.")
 
    offset = len(MAGIC)
    salt = data[offset:offset + SALT_LEN]
    nonce = data[offset + SALT_LEN:offset + SALT_LEN + NONCE_LEN]
    ciphertext = data[offset + SALT_LEN + NONCE_LEN:]
 
    key = derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except InvalidTag:
        raise ValueError("Wrong password, or the file was modified.")
 
    out_path = path[:-len(EXT)] if path.endswith(EXT) else path + ".dec"
    if os.path.exists(out_path):
        raise FileExistsError(f"Refusing to overwrite {out_path}")
    with open(out_path, "wb") as f:
        f.write(plaintext)
    return out_path
 
 
def main():
    parser = argparse.ArgumentParser(description="Basic file encrypter (AES-256-GCM).")
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument("file")
    args = parser.parse_args()
 
    password = getpass("Password: ")
    if args.mode == "encrypt":
        if getpass("Confirm password: ") != password:
            sys.exit("Passwords don't match.")
        print("Wrote", encrypt_file(args.file, password))
    else:
        try:
            print("Wrote", decrypt_file(args.file, password))
        except (ValueError, FileExistsError) as e:
            sys.exit(f"Error: {e}")
 
 
if __name__ == "__main__":
    main()