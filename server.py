import asyncio, json, os, base64, hashlib, hmac, time
import threading
import queue
import websockets

USERS_FILE = "users.json"

clients = {}   # username -> websocket
pubkeys = {}   # username -> session_pub_hex

# secure mode storage (identity_pub + sig) - server只存储/转发，不验证
identity_pub = {}  # username -> ed25519 pub hex
sig_map = {}       # username -> sig hex

# ---------- Server UI ----------
ENABLE_SERVER_UI = True
LOG_Q: "queue.Queue[tuple[str,str]]" = queue.Queue()

def log(level: str, msg: str):
    line = f"{time.strftime('%H:%M:%S')} [{level}] {msg}"
    print(line)
    if ENABLE_SERVER_UI:
        LOG_Q.put((level, line))

def start_server_ui():
    import tkinter as tk
    from tkinter import ttk
    from tkinter.scrolledtext import ScrolledText

    root = tk.Tk()
    root.title("Server Monitor UI (E2EE Chat)")

    frm = ttk.Frame(root, padding=10)
    frm.pack(fill="both", expand=True)

    ttk.Label(frm, text="Server Log Monitor", font=("Segoe UI", 12, "bold")).pack(anchor="w")

    txt = ScrolledText(frm, width=120, height=28, wrap="none")
    txt.pack(fill="both", expand=True, pady=(8, 0))

    txt.tag_config("INFO", foreground="black")
    txt.tag_config("ALERT", foreground="red")
    txt.tag_config("ERROR", foreground="red")

    def poll():
        while True:
            try:
                level, line = LOG_Q.get_nowait()
            except queue.Empty:
                break
            txt.insert("end", line + "\n", level)
            txt.see("end")
        root.after(80, poll)

    poll()
    root.geometry("980x520")
    root.mainloop()

# ---------- helpers: never crash handler on send/close ----------
async def safe_send(ws, data: dict):
    try:
        await ws.send(json.dumps(data))
        return True
    except Exception as e:
        log("ERROR", f"safe_send failed: {e}")
        return False

async def safe_close(ws):
    try:
        await ws.close()
    except Exception as e:
        log("ERROR", f"safe_close failed: {e}")

# ---------- Auth ----------
def load_users_db():
    if not os.path.exists(USERS_FILE):
        return {"users": {}}
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

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

# ---------- WebSocket handler ----------
async def handler(ws):
    username = None
    try:
        async for msg in ws:
            data = json.loads(msg)
            typ = data.get("type")

            if typ == "register":
                requested = data["username"]
                password = data.get("password", "")
                pk = data.get("public_key", "")  # session_pub_hex

                # auth
                if not verify_password(requested, password):
                    await safe_send(ws, {"type": "error", "message": "auth failed"})
                    log("ALERT", f"auth failed '{requested}'")
                    continue

                # SSO: new login kicks old login (do NOT pop maps here)
                if requested in clients and clients[requested] is not ws:
                    old_ws = clients[requested]
                    old_addr = getattr(old_ws, "remote_address", None)
                    new_addr = getattr(ws, "remote_address", None)
                    log("ALERT", f"SSO: kick old session for '{requested}'. old={old_addr} new={new_addr}")

                    # notify old client (optional)
                    await safe_send(old_ws, {
                        "type": "alert",
                        "message": f"你的账号 '{requested}' 在别处登录，你已被下线。"
                    })

                    # close old connection; old handler finally will clean mappings
                    await safe_close(old_ws)

                # optional secure fields (server just stores/relays)
                if "identity_pub" in data and "sig" in data:
                    identity_pub[requested] = data["identity_pub"]
                    sig_map[requested] = data["sig"]
                else:
                    # 如果没带，就别用旧缓存误导（可选：更干净）
                    identity_pub.pop(requested, None)
                    sig_map.pop(requested, None)

                username = requested
                clients[username] = ws
                pubkeys[username] = pk

                await safe_send(ws, {"type": "registered"})
                log("INFO", f"register {username} pk={pk[:16]}...")

            elif typ == "get_pubkey":
                target = data["target"]
                pk = pubkeys.get(target)
                resp = {"type": "pubkey", "target": target, "public_key": pk}

                if target in identity_pub and target in sig_map:
                    resp["identity_pub"] = identity_pub.get(target)
                    resp["sig"] = sig_map.get(target)

                await safe_send(ws, resp)
                log("INFO", f"{username} requested pubkey of {target}")

            elif typ == "send":
                to = data["to"]
                payload = data.get("payload", {})

                peer_ws = clients.get(to)
                if peer_ws:
                    ok = await safe_send(peer_ws, {"type": "recv", "from": username, "payload": payload})
                    if ok:
                        log("INFO", f"forward {username}->{to} nonce={payload.get('nonce','')}")
                    else:
                        await safe_send(ws, {"type": "error", "message": f"{to} connection broken"})
                        log("ERROR", f"forward fail {username}->{to}: connection broken")
                else:
                    await safe_send(ws, {"type": "error", "message": f"{to} not online"})
                    log("ERROR", f"send fail {username}->{to} not online")

            else:
                await safe_send(ws, {"type": "error", "message": "unknown type"})
                log("ERROR", f"unknown type {typ} from {username}")

    except websockets.ConnectionClosed:
        pass
    except Exception as e:
        log("ERROR", f"handler exception: {e}")
    finally:
        # only clean if current mapping still points to me
        if username and clients.get(username) is ws:
            clients.pop(username, None)
            pubkeys.pop(username, None)
            # identity_pub/sig_map 是否要随连接清理：看你需求
            # 如果是“身份长期绑定用户名”，可不删；这里我保守删掉：
            identity_pub.pop(username, None)
            sig_map.pop(username, None)
            log("INFO", f"{username} disconnected")

# ---------- main ----------
async def main():
    host, port = "127.0.0.1", 8765
    log("INFO", f"server ws://{host}:{port}")
    async with websockets.serve(handler, host, port):
        await asyncio.Future()

if __name__ == "__main__":
    if ENABLE_SERVER_UI:
        threading.Thread(target=start_server_ui, daemon=True).start()
    asyncio.run(main())
