# 建议方案：一条 WSS 主链路 + HTTPS 做配对与大文件

对外只暴露 HTTPS 和 WSS，所有端（Android、微信小程序）用同一套契约。

```
Android / 小程序
   │  ① HTTPS  POST /pair              一次性，换 Bearer token
   │  ② WSS    GET  /rpc  (Upgrade)    长连接，承载全部 RPC
   │  ③ HTTPS  POST/GET /blob/<id>     大文件，流式
   ▼
dsh-proxy   TLS 终止 + 握手时鉴权 + 字节拼接
   │
   ▼
Mac (dsh-mobile-bridge)   终止 WebSocket，执行 RPC
```

## D1 WebSocket 由 bridge 终止，proxy 只拼接字节

proxy 转发 Upgrade 请求，**bridge** 回 101（自己算 `Sec-WebSocket-Accept`），
之后 proxy 只做 `copy_bidirectional`。WS 分帧、掩码、ping/pong、关闭握手全在
bridge（Node 侧把 `ws` 挂到隧道 duplex 上即可）。

这条已经实现并有测试（`websocket_upgrade_is_spliced_to_the_bridge`）。

实测代价差（4 B payload，32 并发）：

| proxy 形态 | rps | CPU | RSS |
|---|---:|---:|---:|
| 逐请求 HTTP 再发起 | 59 665 | 2.47 s | 9.1 MB |
| **WSS 字节拼接** | **106 677** | **1.04 s** | **6.7 MB** |
| （参照）老裸 TCP 方案 | 88 418 | 0.58 s | 3.9 MB |

## D2 一个客户端一条管道，RPC 在里面多路复用

帧：`{ id: u32, method: string, payload: bytes }`，二进制 WS 帧。
响应带同一个 `id`。并发靠 id 而不是靠多开连接。

不用「每个 RPC 一个 HTTPS 请求」的原因就是上表第一行：proxy 要为每次调用做
一整轮 HTTP 解析 + 再发起 + 连接池取还，这是 59 µs/请求的固定开销来源。

## D3 大文件走 HTTPS，不走 WS 帧

- 小程序的 `wx.uploadFile` / `wx.downloadFile` 只支持 HTTPS，且给原生进度回调；
  用 WS 帧要自己切片、自己做进度、还要受单帧大小上限约束。
- proxy 侧的流式转发已实现：请求体和响应体都不落内存，64 MiB 上传不会让 RSS 增长。
- blob 用**独立隧道**（连接池已支持每设备多条），避免大文件把 RPC 堵在同一条
  mux 流上产生队头阻塞。

这不是「按端差异化」——两个端的行为完全一致，只是按流量类型分工。

## D4 鉴权只在握手做一次

- `POST /pair` → Bearer token（SHA-256 存储、常数时间比较、文件 0600）。
- WSS 握手带 `Authorization: Bearer <token>`。小程序 `wx.connectSocket` 和
  Android OkHttp 都支持自定义 header，**所以不要把 token 放 query**（会进
  网关日志和 Referer）。
- token 解析成 bridgeKey + 设备私钥，客户端永远看不到也选不了。
- 建立管道之后，每条 RPC 零鉴权开销——这正是性能提升的来源。

## D5 断线是常态，恢复协议是必需项

小程序切后台会断，移动网络会断。协议必须自带恢复，否则用户体验由运气决定：

- 每条 RPC 带单调递增 `id`；bridge 保留最近 N 条响应（按字节数封顶）。
- 重连后客户端先发 `resume{ lastSeenId }`，bridge 重放未确认的响应。
- **写操作必须带幂等键**，否则重放会重复执行。
- 心跳用 WS ping，不要自己造。

这一条比性能重要。上面的 rps 数字在断线面前毫无意义。

## D6 端到端加密留成端上的自由，proxy 零改动

因为 proxy 已经只拼接字节，客户端可以在 WS 二进制帧里再套一层 Noise_IK，
proxy 一个字节都看不懂——**不需要改 proxy 任何一行**。

实测这一层在小 payload 上只值 2.4 % rps / 11 % CPU，所以建议**先不做**：
等真的需要把 proxy 当不可信节点时再加。这是这个设计最大的结构性好处——
安全等级从「架构决策」降级成「端上可后加的选项」。

代价要认清：小程序没有 WebCrypto 的 X25519，得用纯 JS/WASM。握手 X25519
每次 1–3 ms 可接受；ChaCha20-Poly1305 纯 JS 只有几十 MB/s，大文件会在弱机型
上成为新瓶颈。也就是把 CPU 从服务器搬到用户手机。

## D7 proxy 保留不需要解密的配额

鉴权在握手，所以未授权流量在 TLS 之后、开隧道之前就被拒，DoS 不会落到用户的
Mac 上。现成参数继续用：`--max-bridges-per-ip`、`--max-streams-per-bridge`、
`--handshake-timeout-ms`，再加 per-IP 握手速率。

## 与当前代码的差距

已有：TLS 终止、`/pair`、Bearer 校验、`/api/remote.mux` 字节拼接（有测试）、
流式 forward、隧道连接池。

要做：

1. 把 `/api/remote.mux` 定型为 `/rpc`，确立为主链路（proxy 侧改动很小）。
2. bridge 侧把 `ws` 服务端挂到隧道流上，终止 WebSocket。
3. 客户端 RPC 分帧 + D5 的重连/恢复。
4. `/blob/*` 路由复用现成的流式 forward，走独立隧道。
5. 逐请求 `/api/<method>` 保留为兼容路径，但不再是热路径。

## 未核实的前提

微信对 **WS 单帧大小上限** 和 **并发 socket 数** 有明确限制，但开发者文档是
前端渲染的，本次没能抓到正文，**没有把数字写进来**。设计上已经规避：RPC 帧
按 ≤64 KiB 切片，大文件一律走 HTTPS。定稿前请在微信开发者工具里实测这两个值。

另需确认：小程序切后台后 WS 的保活时长——它决定 D5 里 bridge 响应缓存要留多久。
