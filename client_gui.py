import asyncio, json, threading, queue, tkinter as tk
from tkinter import ttk, messagebox
import websockets

from crypto_utils import generate_keypair, derive_session_key, encrypt_aesgcm, decrypt_aesgcm
from history_store import append_encrypted_record, load_and_decrypt_history, history_path
from identity_utils import load_or_create_identity, sign_binding, verify_binding, tofu_check_and_store, fp12

# 你演示时：走代理就填 9001；直连 server 就填 8765
SERVER = "ws://127.0.0.1:9001"

class ClientGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("E2EE Chat Demo (Insecure / Secure)")

        self.kp = generate_keypair()
        self.session_keys = {}  # peer -> key bytes

        # identity (Secure mode)
        self.id_sk = None
        self.id_pk_hex = ""

        # network
        self.ws = None
        self.loop = None
        self.net_thread = None
        self.to_net_q: "queue.Queue[dict]" = queue.Queue()
        self.to_ui_q: "queue.Queue[dict]" = queue.Queue()

        self.connected = False
        self.username = ""
        self.password = ""
        self.peer = ""

        # ✅ Secure mode can be toggled at runtime
        self.secure_mode = tk.BooleanVar(value=False)

        self._build_ui()
        self._poll_ui_queue()

    # ---------------- UI ----------------
    def _build_ui(self):
        frm = ttk.Frame(self.root, padding=10)
        frm.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        frm.columnconfigure(0, weight=1)

        top = ttk.LabelFrame(frm, text="连接信息", padding=10)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)
        top.columnconfigure(3, weight=1)

        ttk.Label(top, text="用户名:").grid(row=0, column=0, sticky="w")
        self.ent_user = ttk.Entry(top)
        self.ent_user.grid(row=0, column=1, sticky="ew", padx=(5, 10))

        ttk.Label(top, text="对方:").grid(row=0, column=2, sticky="w")
        self.ent_peer = ttk.Entry(top)
        self.ent_peer.grid(row=0, column=3, sticky="ew", padx=(5, 0))

        ttk.Label(top, text="密码:").grid(row=1, column=0, sticky="w", pady=(8,0))
        self.ent_pass = ttk.Entry(top, show="*")
        self.ent_pass.grid(row=1, column=1, sticky="ew", padx=(5,10), pady=(8,0))

        # ✅ Secure toggle with command
        ttk.Checkbutton(
            top,
            text="Secure 模式（数字签名防MITM）",
            variable=self.secure_mode,
            command=self.on_toggle_secure
        ).grid(row=1, column=2, columnspan=2, sticky="w", pady=(8, 0))

        self.btn_connect = ttk.Button(top, text="连接/注册", command=self.on_connect)
        self.btn_connect.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8,0))

        self.btn_key = ttk.Button(top, text="获取对方公钥并建密钥(/key)", command=self.on_key, state="disabled")
        self.btn_key.grid(row=2, column=2, columnspan=2, sticky="ew", pady=(8,0))

        self.btn_load = ttk.Button(top, text="加载并解密历史", command=self.on_load_history, state="disabled")
        self.btn_load.grid(row=3, column=2, columnspan=2, sticky="ew", pady=(8,0))

        mid = ttk.LabelFrame(frm, text="聊天窗口（本地明文；网络传密文）", padding=10)
        mid.grid(row=1, column=0, sticky="nsew", pady=(10,10))
        frm.rowconfigure(1, weight=1)
        mid.rowconfigure(0, weight=1)
        mid.columnconfigure(0, weight=1)

        self.txt = tk.Text(mid, height=18, wrap="word")
        self.txt.grid(row=0, column=0, sticky="nsew")
        self.txt.configure(state="disabled")

        bot = ttk.Frame(frm)
        bot.grid(row=2, column=0, sticky="ew")
        bot.columnconfigure(0, weight=1)

        self.ent_msg = ttk.Entry(bot)
        self.ent_msg.grid(row=0, column=0, sticky="ew")
        self.ent_msg.bind("<Return>", lambda e: self.on_send())

        self.btn_send = ttk.Button(bot, text="发送", command=self.on_send, state="disabled")
        self.btn_send.grid(row=0, column=1, padx=(8,0))

        self.status = tk.StringVar(value="未连接")
        ttk.Label(frm, textvariable=self.status).grid(row=3, column=0, sticky="w", pady=(8,0))

        self._log(f"[本机会话公钥 X25519] {self.kp.public_key_bytes.hex()[:16]}...")

    def _log(self, s: str):
        self.txt.configure(state="normal")
        self.txt.insert("end", s+"\n")
        self.txt.see("end")
        self.txt.configure(state="disabled")

    def _set_status(self, s: str):
        self.status.set(s)

    # ------------- Secure toggle -------------
    def on_toggle_secure(self):
        # 1) 清空旧会话密钥（避免混用）
        self.session_keys.clear()
        self._log(f"[系统] Secure 模式切换：{'ON' if self.secure_mode.get() else 'OFF'}")
        self._log("[系统] 已清空会话密钥。模式切换需要重新注册：将断开连接。")

        # 2) 如果当前已连接：强制断开 websocket（让网络线程走到 finally->disconnected）
        if self.connected and self.ws is not None and self.loop is not None:
            try:
                asyncio.run_coroutine_threadsafe(self.ws.close(), self.loop)
            except Exception as e:
                self._log(f"[系统] 关闭连接失败：{e}")

        # 3) 立即把 UI 按钮恢复为“可连接”（不用等网络线程回调也能点）
        #    注意：真正断开后 _handle_ui_event('disconnected') 还会再跑一次，这里不会冲突
        self.connected = False
        self.btn_send.configure(state="disabled")
        self.btn_key.configure(state="disabled")
        self.btn_load.configure(state="disabled")
        self.btn_connect.configure(state="normal")
        self._set_status("未连接（请重新连接/注册）")

    # ------------- UI actions -------------
    def on_connect(self):
        user = self.ent_user.get().strip()
        peer = self.ent_peer.get().strip()
        pwd = self.ent_pass.get().strip()

        if not user or not peer or not pwd:
            messagebox.showwarning("提示", "用户名/对方/密码都要填")
            return

        self.username, self.peer, self.password = user, peer, pwd

        # secure: ensure identity key exists
        if self.secure_mode.get():
            if not self.id_sk or not self.id_pk_hex:
                sk, pk_bytes = load_or_create_identity(self.username)
                self.id_sk = sk
                self.id_pk_hex = pk_bytes.hex()
                self._log(f"[身份公钥 Ed25519] fp={fp12(pk_bytes)}")

        if self.connected:
            messagebox.showinfo("提示", "已连接")
            return

        self.net_thread = threading.Thread(target=self._start_network_thread, daemon=True)
        self.net_thread.start()
        self._set_status("正在连接...")

    def on_key(self):
        if not self.connected:
            return
        self.peer = self.ent_peer.get().strip()
        self.to_net_q.put({"type":"get_pubkey", "target": self.peer})
        self._log(f"[系统] 请求 {self.peer} 公钥...")

    def on_send(self):
        if not self.connected:
            return
        peer = self.ent_peer.get().strip()
        text = self.ent_msg.get().strip()
        if not peer or not text:
            return

        key = self.session_keys.get(peer)
        if key is None:
            messagebox.showwarning("提示", "请先点 /key 建立会话密钥")
            return

        aad = f"{self.username}->{peer}".encode()
        payload = encrypt_aesgcm(key, text.encode("utf-8"), aad=aad)
        self.to_net_q.put({"type":"send", "to": peer, "payload": payload})

        self._log(f"[我 -> {peer}] {text}")
        self.ent_msg.delete(0, "end")

        path = append_encrypted_record(self.username, peer, key, "out", text)
        self._log(f"[系统] 已保存加密记录 -> {path}")

    def on_load_history(self):
        peer = self.ent_peer.get().strip()
        key = self.session_keys.get(peer)
        if not key:
            messagebox.showwarning("提示", "先 /key 建密钥再解密历史")
            return

        path = history_path(self.username, peer)
        recs = load_and_decrypt_history(self.username, peer, key)
        self._log(f"[系统] 历史文件：{path}")
        for r in recs[-50:]:
            if "error" in r:
                self._log(f"[历史] 解密失败: {r['error']}")
            else:
                tag = "我->对方" if r["direction"]=="out" else "对方->我"
                self._log(f"[历史][{tag}] {r['text']}")

    # ---------------- Network thread ----------------
    def _start_network_thread(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._net_main())

    async def _net_main(self):
        try:
            async with websockets.connect(SERVER) as ws:
                self.ws = ws

                session_pub_hex = self.kp.public_key_bytes.hex()
                reg = {
                    "type":"register",
                    "username": self.username,
                    "password": self.password,
                    "public_key": session_pub_hex
                }

                # secure mode: attach identity_pub + signature
                if self.secure_mode.get():
                    if not self.id_sk or not self.id_pk_hex:
                        sk, pk_bytes = load_or_create_identity(self.username)
                        self.id_sk = sk
                        self.id_pk_hex = pk_bytes.hex()

                    sig_hex = sign_binding(self.id_sk, self.username, session_pub_hex)
                    reg["identity_pub"] = self.id_pk_hex
                    reg["sig"] = sig_hex

                await ws.send(json.dumps(reg))
                resp = json.loads(await ws.recv())
                if resp.get("type") != "registered":
                    self.to_ui_q.put({"ui":"error", "msg": f"注册失败: {resp.get('message', resp)}"})
                    return

                self.connected = True
                self.to_ui_q.put({"ui":"connected"})
                await asyncio.gather(self._recv_loop(ws), self._send_loop(ws))

        except Exception as e:
            self.to_ui_q.put({"ui":"error", "msg": f"连接异常: {e}"})
        finally:
            self.connected = False
            self.to_ui_q.put({"ui":"disconnected"})

    async def _send_loop(self, ws):
        while True:
            data = await asyncio.get_event_loop().run_in_executor(None, self.to_net_q.get)
            await ws.send(json.dumps(data))

    async def _recv_loop(self, ws):
        async for msg in ws:
            data = json.loads(msg)
            typ = data.get("type")
            if typ == "pubkey":
                self.to_ui_q.put({
                    "ui":"pubkey",
                    "target": data.get("target"),
                    "public_key": data.get("public_key"),
                    "identity_pub": data.get("identity_pub"),
                    "sig": data.get("sig"),
                })
            elif typ == "recv":
                self.to_ui_q.put({"ui":"recv", "from": data["from"], "payload": data["payload"]})
            elif typ == "error":
                self.to_ui_q.put({"ui":"error", "msg": data.get("message","error")})

    # ---------------- UI queue poll ----------------
    def _poll_ui_queue(self):
        try:
            while True:
                item = self.to_ui_q.get_nowait()
                self._handle_ui_event(item)
        except queue.Empty:
            pass
        self.root.after(80, self._poll_ui_queue)

    def _handle_ui_event(self, item: dict):
        ui = item.get("ui")
        if ui == "connected":
            self._set_status(f"已连接 {self.username} | {SERVER}")
            self._log("[系统] 注册成功")
            self.btn_send.configure(state="normal")
            self.btn_key.configure(state="normal")
            self.btn_load.configure(state="normal")
            self.btn_connect.configure(state="disabled")

        elif ui == "disconnected":
            self._set_status("已断开")
            self._log("[系统] 断开")
            self.btn_send.configure(state="disabled")
            self.btn_key.configure(state="disabled")
            self.btn_load.configure(state="disabled")
            self.btn_connect.configure(state="normal")

        elif ui == "error":
            msg = item.get("msg","")
            self._log(f"[错误] {msg}")
            messagebox.showerror("错误", msg)

        elif ui == "pubkey":
            target = item["target"]
            pk_hex = item["public_key"]
            if pk_hex is None:
                self._log(f"[系统] {target} 不在线或无公钥")
                return

            # secure mode: TOFU + verify signature
            if self.secure_mode.get():
                id_pub = item.get("identity_pub")
                sig = item.get("sig")

                ok, m = tofu_check_and_store(target, id_pub)
                if not ok:
                    self._log(f"[ALERT] {m}")
                    messagebox.showwarning("MITM/TOFU 警告", m)
                    return
                self._log(f"[系统] {m}")

                if not id_pub or not sig or not verify_binding(id_pub, target, pk_hex, sig):
                    m2 = f"{target} 身份签名验证失败（疑似 MITM 公钥替换），拒绝建密钥。"
                    self._log(f"[ALERT] {m2}")
                    messagebox.showwarning("验签失败", m2)
                    return
                self._log(f"[系统] {target} 验签通过 ✅")

            peer_pk = bytes.fromhex(pk_hex)
            key = derive_session_key(self.kp.private_key, peer_pk)
            self.session_keys[target] = key
            self._log(f"[系统] 与 {target} 会话密钥已建立")

        elif ui == "recv":
            sender = item["from"]
            payload = item["payload"]
            key = self.session_keys.get(sender)
            if not key:
                self._log(f"[系统] 收到 {sender} 密文但未建密钥，请先 /key 并把对方填 {sender}")
                return
            aad = f"{sender}->{self.username}".encode()
            try:
                pt = decrypt_aesgcm(key, payload["nonce"], payload["ciphertext"], aad=aad)
                text = pt.decode("utf-8")
                self._log(f"[{sender} -> 我] {text}")
                path = append_encrypted_record(self.username, sender, key, "in", text)
                self._log(f"[系统] 已保存加密记录 -> {path}")
            except Exception as e:
                self._log(f"[系统] 解密失败：{e}")

def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    app = ClientGUI(root)
    root.geometry("780x520")
    root.mainloop()

if __name__ == "__main__":
    main()
