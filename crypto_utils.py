from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

@dataclass
class KeyPair:
    private_key: x25519.X25519PrivateKey
    public_key_bytes: bytes

def generate_keypair() -> KeyPair:
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes_raw()
    return KeyPair(sk, pk)

def derive_session_key(my_sk: x25519.X25519PrivateKey, peer_pk_bytes: bytes, info: bytes = b"e2ee-demo") -> bytes:
    peer_pk = x25519.X25519PublicKey.from_public_bytes(peer_pk_bytes)
    shared = my_sk.exchange(peer_pk)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    return hkdf.derive(shared)

def encrypt_aesgcm(key: bytes, plaintext: bytes, aad: bytes = b"") -> dict:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, aad)
    return {"nonce": nonce.hex(), "ciphertext": ct.hex()}

def decrypt_aesgcm(key: bytes, nonce_hex: str, ciphertext_hex: str, aad: bytes = b"") -> bytes:
    aes = AESGCM(key)
    nonce = bytes.fromhex(nonce_hex)
    ct = bytes.fromhex(ciphertext_hex)
    return aes.decrypt(nonce, ct, aad)
