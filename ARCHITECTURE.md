# 最终方案：一条 WSS 字节管道

对外只有 HTTPS 和 WSS。端到端加密保留，公网 proxy 看不到任何明文。

```
Android / 小程序
   │  wss://<host>/tunnel        ← 唯一的客户端契约
   │    └ 帧内：37 字节前导头 + Noise_IK 会话（proxy 解不开）
   ▼
dsh-proxy   TLS 终止 → 拆 WebSocket 帧 → 按前导头转发字节
   ▼
Mac (dsh-mobile-bridge)   Noise_IK 对端 + 设备白名单 = 真正的鉴权
```

## 为什么是这个形状

两个客户端都已经拥有完整的 Noise 栈，而且都坐在一个干净的字节流接口上：
小程序是 `SocketFactory.connect() -> {write, close}`，Android 是
`javax.net.SocketFactory` 包一个 `Socket` 喂给 OkHttp。所以把裸 TCP 换成 WSS
之后，上面的 Noise / mux / HTTP 一行都不用改——**变的只有谁来搬字节**。

实测（4 字节 payload，32 并发，同一 bridge、同一压测器）：

| proxy 形态 | rps | CPU | RSS |
|---|---:|---:|---:|
| 逐请求 HTTP 再发起（托管 RPC） | 59 665 | 2.47 s | 9.1 MB |
| **字节管道** | **106 677** | **1.04 s** | **6.7 MB** |
| 参照：老裸 TCP 方案 | 88 418 | 0.58 s | 3.9 MB |

字节管道比老方案还快 21 %，同时满足「只暴露 HTTPS/WSS」。它比托管 RPC 快，是因为
proxy 不再为每次调用解析并重建一个 HTTP 请求——这一项占了全部差距的九成以上，
「少做一层加密」只值 2.4 %。

## 鉴权

| 层 | 证明了什么 | 在哪儿 |
|---|---|---|
| TLS 1.3 | 客户端连到的是真的 proxy | proxy |
| Noise_IK | 这台设备持有已配对的静态密钥 | 手机 ↔ Mac（proxy 解不开） |
| 设备白名单 | 这个设备键在配对时被批准过 | Mac |

`/tunnel` 不校验任何 token，也无从校验：里面的会话是手机与 Mac 之间的，proxy
没有密钥。proxy 在这条路上欠的是**准入控制**而不是身份认证：

- `--max-clients-per-ip`：TLS 连接在握手之前就按来源地址计数封顶。
- `--max-streams-per-bridge`：一台 Mac 同时承载的流有上限。
- 未知 bridgeKey 直接静默丢弃，不回一个字节。

配对仍然在隧道内完成（一次性配对码随 Noise_IK 第一条消息发给 Mac），所以 proxy
**不需要 `/pair`、不需要 token 存储、不需要磁盘**。

## 实现状态

| 组件 | 改动 | 验证 |
|---|---|---|
| dsh-proxy | `src/ws.rs` 帧编解码 + `/tunnel` 路由 + `serve_client` 泛化 | 24 项测试通过，含端到端 Noise、7 字节分片、ping/pong |
| dsh-mobile-bridge | 无需改动 | — |
| dsh-miniapp | 新增 `wsSocket.ts`，两处默认工厂切换 | typecheck 通过 |
| dsh-androidapp | 新增 `WsTunnel.kt`，`NoiseSocket` 换载体 | **未编译**（本机无 Gradle 8.9 接受的 JDK） |

## 还没做的清理

proxy 里仍留着上一轮的托管 RPC 表面（`/pair`、Bearer、连接池、`--state`、
proxy 侧 Noise_IK）和裸 TCP 客户端路径。按「只支持 HTTPS/WSS」它们应当整体删除，
删掉之后 proxy 会回到「无磁盘、无状态」，代码量大幅下降。这需要同时改写
`tests/tunnel.rs` 的客户端侧（11 项测试现在用裸 TCP 建连），所以单独做。
