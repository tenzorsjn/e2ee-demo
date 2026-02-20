import os, json, base64, hashlib
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

ID_DIR = "identity"
TRUST_DB = os.path.join(ID_DIR, "trusted_peers.json")

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def fp12(pub_bytes: bytes) -> str:
    return hashlib.sha256(pub_bytes).hexdigest()[:12]

def _ensure_dir():
    os.makedirs(ID_DIR, exist_ok=True)

def identity_key_path(username: str) -> str:
    safe = "".join(c for c in username if c.isalnum() or c in ("-", "_")) or "user"
    return os.path.join(ID_DIR, f"{safe}_ed25519.json")

def load_or_create_identity(username: str) -> Tuple[ed25519.Ed25519PrivateKey, bytes]:
    _ensure_dir()
    path = identity_key_path(username)
    if os.path.exists(path):
        data = json.load(open(path, "r", encoding="utf-8"))
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(_b64d(data["sk_b64"]))
        pk_bytes = _b64d(data["pk_b64"])
        return sk, pk_bytes

    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    json.dump({"sk_b64": _b64e(sk_bytes), "pk_b64": _b64e(pk_bytes)},
              open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return sk, pk_bytes

def sign_binding(identity_sk: ed25519.Ed25519PrivateKey, username: str, session_pub_hex: str) -> str:
    msg = (username + "|" + session_pub_hex).encode("utf-8")
    return identity_sk.sign(msg).hex()

def verify_binding(identity_pub_hex: str, username: str, session_pub_hex: str, sig_hex: str) -> bool:
    try:
        pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(identity_pub_hex))
        msg = (username + "|" + session_pub_hex).encode("utf-8")
        pk.verify(bytes.fromhex(sig_hex), msg)
        return True
    except Exception:
        return False

def _load_trust_db() -> dict:
    _ensure_dir()
    if not os.path.exists(TRUST_DB):
        return {"peers": {}}
    return json.load(open(TRUST_DB, "r", encoding="utf-8"))

def _save_trust_db(db: dict):
    _ensure_dir()
    json.dump(db, open(TRUST_DB, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

def tofu_check_and_store(peer: str, identity_pub_hex: Optional[str]) -> Tuple[bool, str]:
    if not identity_pub_hex:
        return False, "对方没有提供身份公钥 identity_pub"

    db = _load_trust_db()
    peers = db.setdefault("peers", {})
    old = peers.get(peer)

    if old is None:
        peers[peer] = identity_pub_hex
        _save_trust_db(db)
        return True, f"TOFU：首次绑定 {peer} 身份指纹={fp12(bytes.fromhex(identity_pub_hex))}"

    if old != identity_pub_hex:
        return False, (
            f"TOFU 警告：{peer} 身份公钥变化！\n"
            f"old_fp={fp12(bytes.fromhex(old))} new_fp={fp12(bytes.fromhex(identity_pub_hex))}\n"
            f"疑似 MITM，拒绝建立会话密钥。"
        )

    return True, f"TOFU：{peer} 身份公钥一致（fp={fp12(bytes.fromhex(identity_pub_hex))})"
