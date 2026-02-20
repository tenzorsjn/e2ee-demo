<<<<<<< HEAD
# e2ee-demo
E2EE chat demo (ECDH + AES-GCM) with MITM attack &amp; signature defense demo.
=======
# E2EE MITM Demo (Insecure vs Secure)

## 环境
conda create -n e2ee-mitm python=3.11 -y
conda activate e2ee-mitm
pip install -r requirements.txt

## 运行顺序（本机三窗口演示）
1) 启动 server
   python server.py

2) 启动 Mallory MITM 代理（UI）
   python mitm_proxy_ui.py
   代理监听 ws://127.0.0.1:9001 并转发到 ws://127.0.0.1:8765

3) 启动两个客户端 GUI（分别扮演 alice 和 bob）
   python client_gui.py   (alice, peer=bob, pass=alicepass)
   python client_gui.py   (bob, peer=alice, pass=bobpass)

客户端里 SERVER 默认走 ws://127.0.0.1:9001（经过 Mallory），可直接演示抓包。

---

## 演示1：Insecure（成功 MITM，Mallory 看到明文）
- 两个客户端都不要勾选 Secure 模式
- alice 与 bob 都点击 /key 建立密钥
- 互发消息
- Mallory UI 中会出现 [Mallory PLAINTEXT] 行（明文可见）

---

## 演示2：Secure（数字签名防御，MITM 失败）
- 两个客户端都勾选 Secure 模式
- alice/bob 注册时会生成 identity/ 下的 Ed25519 身份密钥文件
- /key 时会做 TOFU + 验签
- Mallory 仍替换 pubkey，但会导致验签失败，客户端弹窗报警并拒绝建立会话密钥
- Mallory UI 无法出现明文解密成功

---

## 注意
- Secure 模式首次 TOFU 会记录对方身份指纹，后续变化会报警。
>>>>>>> 4358c49 (init)
