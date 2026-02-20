```md
# E2EE Chat Demo（ECDH + AES-GCM）& MITM Demo（Insecure vs Secure）

本项目用于密码学课程演示，包含：
- **端到端加密聊天（E2EE）**：X25519(ECDH) 协商会话密钥 + HKDF 派生 + AES-GCM 加密（含完整性校验），聊天记录本地以密文保存。
- **中间人攻击（MITM）与防御**：
  - **Insecure**：Mallory 作为代理替换公钥并“解密→重加密→转发”，可在 Mallory UI 看到明文。
  - **Secure**：使用 Ed25519 数字签名 + TOFU（首次信任）绑定身份与公钥，阻止公钥替换型 MITM。

---

## 1. 环境配置（Anaconda）

```bash
conda create -n e2ee-mitm python=3.11 -y
conda activate e2ee-mitm
pip install -r requirements.txt
````

依赖：

* `websockets`
* `cryptography`
* `tkinter`（Python 自带；Windows 通常默认可用）

---

## 2. 端口与监听关系

本项目默认使用 2 个 WebSocket 端口：

### ✅ Server（真实服务器）

* **监听**：`ws://127.0.0.1:8765`
* **作用**：注册/转发消息（只转发密文，不负责加解密）

对应：`server.py`

### ✅ Mallory Proxy（代理）

* **代理**：`ws://127.0.0.1:9001`  （客户端连接这个）
* **转发到**：`ws://127.0.0.1:8765`（转发到真实服务器）

对应：`mitm_proxy_ui.py`

> 为什么要两个端口？
> 因为 Mallory 要“夹在中间”，客户端连到 9001（Mallory），Mallory 再连到 8765（Server），这样就能监听/篡改密钥交换与密文转发，实现 MITM 演示。

---

## 3. 运行顺序（单机三窗口即可完成演示）

### 0）生成用户口令库（首次需要）

```bash
python make_users.py
```

建议创建示例账号（按脚本提示输入）：

* `alice / alice123`
* `bob / bob123`

生成文件：`users.json`

---

### 1）启动服务器（Server）

```bash
python server.py
```

Server 监听：`ws://127.0.0.1:8765`

---

### 2）启动 Mallory 代理（带 UI）

```bash
python mitm_proxy_ui.py
```

Mallory 监听：`ws://127.0.0.1:9001`
转发到 Server：`ws://127.0.0.1:8765`

---

### 3）启动两个客户端 GUI（Alice / Bob）

分别打开两个终端：

```bash
python client_gui.py
python client_gui.py
```

在 GUI 中分别输入：

* Alice：用户名 `alice`，对方 `bob`，密码 `alice123`
* Bob：用户名 `bob`，对方 `alice`，密码 `bob123`

客户端默认连接 **Mallory**：`ws://127.0.0.1:9001`

---

## 4. 演示

演示受限只有一台电脑，同时打开多个终端模拟三种角色：

* **Server**：真实服务器
* **Alice / Bob**：两个客户端（开两个 GUI 窗口即可）
* **Mallory**：中间人代理（单独 UI 窗口显示监听内容）

它们都运行在同一台电脑，但通信仍然通过 **WebSocket 端口**走“网络协议流程”。
所以在录屏中清晰展示：

* 真实传输的是 **nonce + ciphertext（密文）**
* Insecure 下 Mallory 能看到 **PLAINTEXT（明文）**
* Secure 下客户端会 **报警/拒绝建立密钥**

---

## 5. 演示 A：纯 E2EE（不强调 MITM，只讲 ECDH + AES-GCM）

### 方法 1：仍经过 Mallory，但关闭攻击模式（UI 可做“抓包”展示）

* 在 Mallory UI 中关闭攻击/篡改功能（只记录密文）
* Alice/Bob 建立密钥（/key）后正常聊天
* 你可以强调：Mallory 看到的是密文，无法解密（无密钥）

### 方法 2：客户端直连 Server（完全绕过 Mallory）

* 将 `client_gui.py` 中 `SERVER` 改为：`ws://127.0.0.1:8765`
* 不启动 `mitm_proxy_ui.py`

此时演示重点：

1. ECDH 交换公钥后得到相同会话密钥
2. AES-GCM 加密传输（密文）
3. 本地聊天记录是密文保存，可加载解密显示

---

## 6. 演示 B：Insecure（MITM 成功，Mallory 看到明文）

步骤：

1. 两个客户端都 **不勾选 Secure**
2. Alice/Bob 都点击 **/key**
3. 互发消息（建议发“机密信息”更直观）
4. 观察 Mallory UI：出现类似 **\[Mallory PLAINTEXT]** 的明文输出

解释要点：

* Mallory 替换公钥，使双方分别与 Mallory 建立密钥
* Mallory 用与 Alice 的密钥解密，再用与 Bob 的密钥重新加密转发
* 所以 Alice/Bob 看起来一切正常，但隐私泄露

---

## 7. 演示 C：Secure（签名防御，MITM 失败）

步骤：

1. 两个客户端都 **勾选 Secure**
2. 首次运行会在 `identity/` 下生成 Ed25519 身份密钥，并记录 TOFU 信任信息
3. 点击 **/key** 时会进行验签/指纹校验
4. Mallory 若替换 pubkey → **验签失败**
   客户端弹窗报警并拒绝建立会话密钥
   Mallory UI 也无法再看到成功解密的明文

---

## 8. 文件结构

* `server.py`：转发服务器（认证 + 单点登录 + 转发密文）
* `client_gui.py`：Tkinter 客户端（Insecure / Secure）
* `mitm_proxy_ui.py`：Mallory 代理 + UI（监听/篡改/明文展示）
* `crypto_utils.py`：X25519/HKDF/AES-GCM
* `history_store.py`：聊天记录密文保存与加载解密
* `identity_utils.py`：Ed25519 签名 + TOFU 信任记录
* `make_users.py`：用于生成示例用户签名 `users.json`（PBKDF2-HMAC-SHA256）

---

## 9. 局域网多电脑演示

> 目标：Alice、Bob 分别在两台电脑上运行，Server（和/或 Mallory）在另一台电脑上运行。

### 9.1 修改监听地址（Server / Mallory）

* Server：把 `websockets.serve(..., "127.0.0.1", 8765)` 改为 `0.0.0.0`

  * 这样局域网其它电脑才能连进来
* Mallory 同理：监听 `0.0.0.0:9001`，转发到 `Server_IP:8765`

### 9.2 客户端 SERVER 改为局域网 IP

例如服务器电脑 IP 为 `192.168.1.10`：

* 直连 Server：`ws://192.168.1.10:8765`
* 经过 Mallory：`ws://192.168.1.10:9001`

### 9.3 防火墙放行端口

Windows 防火墙允许入站：

* 8765（Server）
* 9001（Mallory）

