import asyncio, json, os, base64, hashlib, hmac, time
import websockets

USERS_FILE = "users.json"

clients = {}   # username -> websocket
pubkeys = {}   # username -> session_pub_hex

# secure mode storage (identity_pub + sig)
identity_pub = {}  # username -> ed25519 pub hex
sig_map = {}       # username -> sig hex

def log(level, msg):
    ts = time.strftime("%H:%M:%S")
    print(f"{ts} [{level}] {msg}")

def load_users_db():
    if not os.path.exists(USERS_FILE):
        return {"users": {}}
    return json.load(open(USERS_FILE, "r", encoding="utf-8"))

def verify_password(username: str, password: str) -> bool:
    db = load_users_db()
    rec = db.get("users", {}).get(username)
    if not rec:
        return False
    salt = base64.b64decode(rec["salt_b64"])
    iters = int(rec.get("iterations", 200_000))
    want = base64.b64decode(rec["hash_b64"])
    got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=32)
    return hmac.compare_digest(got, want)

async def handler(ws):
    username = None
    try:
        async for msg in ws:
            data = json.loads(msg)
            typ = data.get("type")

            if typ == "register":
                requested = data["username"]
                password = data.get("password", "")
                pk = data["public_key"]  # session_pub_hex

                # auth
                if not verify_password(requested, password):
                    await ws.send(json.dumps({"type": "error", "message": "auth failed"}))
                    log("ALERT", f"auth failed '{requested}'")
                    continue

                # single sign-on
                if requested in clients and clients[requested] is not ws:
                    await ws.send(json.dumps({"type": "error", "message": "already logged in"}))
                    log("ALERT", f"reject duplicate login '{requested}'")
                    continue

                # optional secure fields (server just stores/relays; verification is on client side)
                if "identity_pub" in data and "sig" in data:
                    identity_pub[requested] = data["identity_pub"]
                    sig_map[requested] = data["sig"]

                username = requested
                clients[username] = ws
                pubkeys[username] = pk
                await ws.send(json.dumps({"type": "registered"}))
                log("INFO", f"register {username} pk={pk[:16]}...")

            elif typ == "get_pubkey":
                target = data["target"]
                pk = pubkeys.get(target)
                resp = {"type": "pubkey", "target": target, "public_key": pk}
                # if secure info exists, include it
                if target in identity_pub and target in sig_map:
                    resp["identity_pub"] = identity_pub.get(target)
                    resp["sig"] = sig_map.get(target)
                await ws.send(json.dumps(resp))
                log("INFO", f"{username} requested pubkey of {target}")

            elif typ == "send":
                to = data["to"]
                payload = data["payload"]
                if to in clients:
                    await clients[to].send(json.dumps({"type": "recv", "from": username, "payload": payload}))
                    log("INFO", f"forward {username}->{to} nonce={payload.get('nonce','')}")
                else:
                    await ws.send(json.dumps({"type": "error", "message": f"{to} not online"}))
                    log("ERROR", f"send fail {username}->{to} not online")

            else:
                await ws.send(json.dumps({"type": "error", "message": "unknown type"}))
                log("ERROR", f"unknown type {typ} from {username}")

    except websockets.ConnectionClosed:
        pass
    finally:
        if username and clients.get(username) is ws:
            clients.pop(username, None)
            pubkeys.pop(username, None)
            log("INFO", f"{username} disconnected")

async def main():
    host, port = "127.0.0.1", 8765
    log("INFO", f"server ws://{host}:{port}")
    async with websockets.serve(handler, host, port):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
