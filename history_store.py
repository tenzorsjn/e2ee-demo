import os, json, time
from typing import List, Dict
from crypto_utils import encrypt_aesgcm, decrypt_aesgcm

HIST_DIR = "history"

def history_path(me: str, peer: str) -> str:
    os.makedirs(HIST_DIR, exist_ok=True)
    safe = lambda s: "".join(c for c in s if c.isalnum() or c in ("-", "_"))
    return os.path.join(HIST_DIR, f"{safe(me)}__{safe(peer)}.jsonl")

def append_encrypted_record(me: str, peer: str, key: bytes, direction: str, text: str) -> str:
    path = history_path(me, peer)
    aad = f"{me}<->{peer}".encode()
    payload = encrypt_aesgcm(key, text.encode("utf-8"), aad=aad)
    rec = {
        "ts": time.time(),
        "direction": direction,
        "nonce": payload["nonce"],
        "ciphertext": payload["ciphertext"],
    }
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return path

def load_and_decrypt_history(me: str, peer: str, key: bytes) -> List[Dict]:
    path = history_path(me, peer)
    if not os.path.exists(path):
        return []
    out = []
    aad = f"{me}<->{peer}".encode()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            try:
                pt = decrypt_aesgcm(key, rec["nonce"], rec["ciphertext"], aad=aad)
                out.append({"direction": rec["direction"], "text": pt.decode("utf-8"), "ts": rec["ts"]})
            except Exception as e:
                out.append({"direction": rec.get("direction","?"), "error": str(e), "ts": rec.get("ts",0)})
    return out
