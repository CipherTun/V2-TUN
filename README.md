<div align="center">

<img src="docs/assets/banner.svg" alt="v2-tun: Xray-free tunnel library in Go" width="100%">

<br>

![module](https://img.shields.io/badge/module-io.surprise.vpn-22d3ee?style=for-the-badge&labelColor=0b1020)
![android](https://img.shields.io/badge/Android-gomobile-a78bfa?style=for-the-badge&labelColor=0b1020)
![ci](https://img.shields.io/badge/CI-vet%20%2B%20test%20--race-34d399?style=for-the-badge&labelColor=0b1020)
![cli](https://img.shields.io/badge/CLI-Termux%20ready-f472b6?style=for-the-badge&labelColor=0b1020)

**[Protocols](#-protocols)** • **[SSH over WebSocket](#-ssh-over-websocket-payload-no-tls-needed)** • **[Payload](#-payload-http-injector-style)** • **[Failover](#-failover-double-hop-and-keepalive)** • **[Routing](#-routing-split-tunneling-mux-and-udpgw)** • **[CLI](#-command-line)** • **[App API](#-app-api-gomobile)** • **[Roadmap](ROADMAP.md)**

</div>

<img src="docs/assets/divider.svg" alt="" width="100%">

## ⚡ What it is

Xray-free tunnel library in Go. Module/namespace: `io.surprise.vpn`.

<img src="docs/assets/flow.svg" alt="Connection chain: tcp, payload pre-tls, tls or reality, payload post-tls, transport, protocol" width="100%">

Chain: tcp -> [payload pre-tls] -> tls or reality (SNI, ALPN, uTLS fingerprint) -> [payload post-tls] -> ws / httpupgrade / h2 / grpc / xhttp -> protocol.

Protocols: trojan, vless, vmess (AEAD + legacy alterId>0, plaintext ok), shadowsocks (AEAD + legacy stream), ssh
(max-compat algorithm lists by default; override via `advanced`), socks5 (user/password), socks4/4a, http and https proxies (CONNECT, Basic auth),
hysteria 2 and hysteria 1.

Local proxy: `mobile.Start(json, "127.0.0.1:10808")` runs SOCKS5 through the tunnel (feed it to tun2socks for TUN mode).

```bash
go mod tidy && go vet ./... && go test ./...      # build and test
gomobile bind -target=android -javapkg=io.surprise -o v2tun.aar io.surprise.vpn/mobile   # Android
```

<img src="docs/assets/divider.svg" alt="" width="100%">

## 🧩 Protocols
| `protocol` | Notes |
| --- | --- |
| `vless`, `vmess`, `trojan`, `shadowsocks` | TCP and UDP, Mux.Cool, any transport below; `vless` also takes `flow: xtls-rprx-vision` (see XTLS Vision) |
| `ssh` | direct-tcpip; UDP through udpgw. TLS is optional, see SSH over WebSocket. Login with `password`, or `privateKey` (PEM text or a file path) plus `passphrase` when the key is encrypted |
| `socks5` (`socks`) | CONNECT, optional username/password; UDP through udpgw |
| `socks4` (`socks4a`) | CONNECT; the user id is `username`; host names use SOCKS4a |
| `http` / `https` | CONNECT with Basic auth (`username`/`password`) and extra headers (`proxyHeaders`); `https` needs `tls.enabled` |
| `hysteria2` (`hy2`) | QUIC, TCP and UDP, Salamander obfs, certificate pinning |
| `hysteria` (`hy`) | Hysteria 1 (protocol v3), TCP and UDP, xplus obfs |

Socks and http proxies take the whole chain underneath them, so a payload, TLS with a fake SNI or a WebSocket can sit between you and the proxy.
Share links: `socks5://user:pass@host:1080`, `socks4://host:1080`, `http://user:pass@host:8080`, `https://host:443`, `hysteria2://..`, `hysteria://..`.

<img src="docs/assets/divider.svg" alt="" width="100%">

## 🔌 SSH over WebSocket (payload, no TLS needed)
The usual injector setup is host:port, username, password, a payload and optionally an HTTP proxy. TLS is the user's choice (`tls.enabled`), never required. There are **no payload presets**: you write the payload yourself.
```json
{"protocol":"ssh","server":"ssh.example.com","port":80,"username":"user","password":"pass",
 "payload":{"template":"GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]","host":"bug.example.com"}}
```
The server answers `101 Switching Protocols`, so the reply is read and dropped before SSH starts. That happens automatically for an HTTP-looking payload on a plain tcp stream; set `expectResponse` to `true` or `false` to override.

**Plain or framed is detected for you.** After an `Upgrade: websocket` payload is accepted, the first bytes from the server decide: the SSH banner means a plain tunnel, a WebSocket frame means a framed one, and the library then frames and unframes by itself. No path, host or mode setting is needed (a server that stays silent for 1.5 s is treated as plain). This applies to protocol `ssh` on a plain tcp stream.

Through an HTTP proxy (remote proxy mode), the TCP connection goes to the proxy and the payload names your real server with `[server_host_port]`, while `[host]` keeps carrying the bug host:
```json
{"protocol":"ssh","server":"ssh.example.com","port":22,"username":"user","password":"pass",
 "payload":{"template":"CONNECT [server_host_port] HTTP/1.1[crlf]Host: [host][crlf][crlf]GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]","host":"bug.example.com","proxy":"1.2.3.4:8080"}}
```
One reply is read per HTTP request line in the payload (here two: the proxy's reply, then the server's 101); `expectResponses` overrides the count.

With `"network":"ws"` (or `httpupgrade`) the order is **proxy, payload, WebSocket, SSH**: the TCP connection goes to the remote proxy, the payload is sent and answered, then the WebSocket handshake runs on top and SSH runs inside it.

### Target tags
`[host]` / `[host_port]` / `[netData]` use the payload `host` (the bug host) when one is set. `[server]`, `[server_port]` and `[server_host_port]` always mean the real server from the config, and `[ip]` / `[ip_port]` are the real server's resolved address, also behind a remote proxy (where the socket itself connects to the proxy). Existing payloads keep working: `[host_port]` still means the same as before.

### Replies are checked automatically
There is no response changer to configure. Like HTTP Custom, HTTP Injector and NetMod, the payload layer accepts every reply below 400 (`101`, any `2xx`, any `3xx`) and refuses `4xx` and `5xx`. Only the status line and headers of a reply are read, so a server that sends a body with its fake status should be avoided. The old `responseMap` and `expectCodes` settings are gone; a config that still has them loads, and they are ignored.

<img src="docs/assets/divider.svg" alt="" width="100%">

## 🧪 Payload (HTTP Injector style)
`"payload": {"template": "CONNECT [server_host_port] HTTP/1.1[crlf]Host: [host][crlf][crlf]", "host": "bug.example.com", "stage": "pre-tls", "expectResponse": true, "expectResponses": 1, "vars": {"token": "abc"}, "proxy": "1.2.3.4:8080"}`
- `template`: the payload, written by you (tags are listed at the top of `payload/payload.go`: `[crlf]`, `[host_port]`, `[server_host_port]`, `[netData]`, `[split]`, `[delay=500]`, `[random=a|b]`, `[rotate=a|b]`, `[var=token]`, `[b64=...]`, `[rand_ua]`, ...; `[ssh]` is `[host_port]` and `[real_raw]` is `[raw]`). A bare preset name such as `@connect` is rejected.
- `stage`: `pre-tls` (default) sends the payload right after the TCP connect; `post-tls` sends it inside TLS.
- `proxy`: remote proxy mode (see above). Pre-tls only.
- `expectResponse`, `expectResponses`: whether and how many HTTP replies are read before the protocol starts (see above). The status of a reply is never configurable: below 400 passes.
- `host`, `method`, `userAgent`, `vars` fill `[host]`, `[method]`, `[ua]` and `[var=name]`; `[sni]` takes the TLS/REALITY server name.

Preview any template without connecting: `v2tun payload -c config.json` or `mobile.PreviewPayload(template, host, server, port)`.

<img src="docs/assets/divider.svg" alt="" width="100%">

## 🛡️ Failover, double hop and keepalive
- **Backups**: `backups` lists complete outbound configs (another server, bug host, payload or protocol) tried in order when the main one fails; the one that worked last is tried first next time. `failoverTimeoutSec` limits each attempt (default 12). `routing`, `udpgw` and `directDns` belong to the top-level config only, and backups cannot nest.
- **Latency sort**: with `backups`, `latencySortSec: N` measures every N seconds how fast each server accepts a TCP connection and, after a failure, tries the quickest first (the one in use stays first until it fails). Hysteria and QUIC cannot be probed with a TCP connect and rank between answering and unreachable servers.
- **SSH double hop**: `advanced.sshNext` turns the `ssh` protocol into two hops. The top-level server and credentials are the jump host, reached through the whole dial chain (payload, TLS, WebSocket, ...); `sshNext` is the second host, reached from inside the jump session, and is where traffic exits. The second hop takes `password`, or `privateKey` with `passphrase`.
- **Host key pinning**: `advanced.sshHostKey` (and `sshNext.hostKey`) take `SHA256:...` as printed by `ssh-keygen -l`, or 64 hex characters. Empty accepts any key.
- **Encrypted keys**: `passphrase` (and `sshNext.passphrase`) decrypts an encrypted `privateKey`. An encrypted key without a passphrase fails with a clear error instead of an authentication failure; a key that is not encrypted ignores the passphrase.
- **Keepalive**: `ws.pingSec` sends a WebSocket ping every N seconds on the ws transport so carriers and CDNs do not drop an idle tunnel; `idleTimeoutSec` closes a tunneled connection after that many seconds without data.
- Which outbound is live: `mobile.ActiveOutbound()` (0 is the main config, 1 the first backup, -1 when nothing runs).

<img src="docs/assets/divider.svg" alt="" width="100%">

## 🐉 Hysteria
```json
{"protocol":"hysteria2","server":"example.com","port":443,"password":"secret",
 "tls":{"sni":"example.com","allowInsecure":false},
 "hysteria":{"obfs":"salamander-password","pinSha256":""}}
```
- **Hysteria 2**: `password` is the auth string, `hysteria.obfs` the Salamander password, `hysteria.pinSha256` pins the server certificate (replaces CA checks), `hysteria.downMbps` advertises your receive rate (0 lets the server decide). Port hopping is not supported.
- **Hysteria 1**: `password` is the auth string, `hysteria.obfs` the xplus password, `hysteria.alpn` defaults to `hysteria`. `upMbps` (default 10) and `downMbps` (default 50) are required by the server, and **the server sends at the `downMbps` you declare**, so set it to what your link can take. faketcp and wechat-video are not supported.
- Both run over one QUIC connection that is re-opened when it dies. TCP is a stream per connection and UDP rides on QUIC datagrams (fragmented when needed). They bring their own QUIC/TLS: `payload`, `reality`, `fragment` and other transports are rejected for them, and so are `tls.pinSha256` and `tls.verifyName` (use `hysteria.pinSha256`).
- There is no Brutal congestion control in the client (quic-go has no hook for it), so uploads use quic-go's default.
- Links: `hysteria2://auth@host:443/?sni=..&insecure=1&obfs=salamander&obfs-password=..&pinSHA256=..` and `hysteria://host:443?auth=..&peer=..&insecure=1&upmbps=..&downmbps=..&alpn=..&obfs=xplus&obfsParam=..`.

> [!WARNING]
> Written from the published protocol specs and checked against loopback tests only. Try it against your own server before relying on it.

<img src="docs/assets/divider.svg" alt="" width="100%">

## 🚇 Transports
tcp, ws, httpupgrade, h2 (http), grpc (gun, no grpc lib), quic (single stream), xhttp. TLS: allowInsecure, SNI, ALPN, uTLS fingerprints, certificate pinning and a verify name (below).
Not yet: mKCP, the REALITY spiderX crawl.

### TLS certificate pinning and verify name
```json
"tls": {"enabled": true, "sni": "cdn.example.com", "pinSha256": ["a1b2...64 hex characters"], "verifyName": "origin.example.com"}
```
- `pinSha256`: hex SHA-256 of a DER certificate (colons allowed). The handshake succeeds only when a certificate of the server's chain matches one of the pins. It is checked on top of normal verification and also with `allowInsecure`, so a self-signed server can be trusted by pin alone. `openssl s_client -connect host:443 </dev/null | openssl x509 -outform DER | sha256sum` prints the value.
- `verifyName`: verify the certificate for this name instead of the SNI, for a front that sends one name and presents another. The chain is still checked against the system roots, and `allowInsecure` turns the check off.
- Both need `tls.enabled` and are rejected (rather than silently ignored) with REALITY, the quic transport, or the hysteria protocols, which do their own TLS. Encrypted Client Hello is not supported.
- Covered by loopback tests (a real TLS handshake against a local server for the pin); `verifyName` is only tested for its failure paths, so try it against your own server.

### REALITY
Set `"reality": {"publicKey": "<pbk>", "shortId": "<sid hex>", "serverName": "<cover site>", "fingerprint": "chrome"}`
(it replaces the `tls` layer; it works with tcp, h2, grpc and xhttp, not quic). Share links with `security=reality&pbk=..&sid=..&sni=..&fp=..`
are parsed by `ParseLink`. A wrong key, shortId or server name fails with a clear error instead of hanging. Test it against your own server before relying on it.

### XTLS Vision
Set `"flow": "xtls-rprx-vision"` on a `vless` config, or use a share link with `flow=xtls-rprx-vision` (`-udp443` is accepted too). It needs the plain
`tcp` transport with `tls.enabled` or `reality`. `New` and `ParseLink` reject it with ws/h2/grpc/xhttp/quic, without TLS or REALITY, with `mux`, and on any
protocol other than `vless` (hysteria brings its own QUIC/TLS, so it never applies there). A pre-tls `payload` and `fragment` still work: the record layer
Vision needs sits directly under TLS/REALITY, above them.
The client pads the inner TLS handshake and follows the server's switch to direct copy. It is based on Xray-core's behaviour and has only been
tested against its own framing, not a live server, so try it against your own inbound before relying on it. Other flows are rejected.

### XHTTP, TLS fragmenting and share links
- XHTTP/SplitHTTP: `network: "xhttp"`, `xhttpMode`: auto|packet-up|stream-up|stream-one, tuning via `xhttp: {xPaddingBytes, scMaxEachPostBytes, scMinPostsIntervalMs}`. Verify against your Xray version.
- TLS fragmenting: `"fragment": {"length":[10,40], "interval":[5,20]}`.
- Share links: `mobile.ParseLink(link)` -> JSON config (vless, vmess, trojan, ss, ssh, socks, http, hysteria).
- UDP relay: VLESS (cmd 2), VMess (cmd 2), Trojan (UDP ASSOCIATE), Shadowsocks (native UDP), Hysteria 1 and 2. TUN forwards all UDP through it; SSH, SOCKS and HTTP proxies have no UDP (use `udpgw`).

<img src="docs/assets/divider.svg" alt="" width="100%">

## 🧭 Routing, split tunneling, Mux and udpgw
- Routing (`routing`): rules with domain (`full:`, `domain:`, `keyword:`, `regexp:`, `dotless:`), ip (CIDR, `geoip:private`), port, network, sniffed `protocol`
  (http, tls, bittorrent, ssh; needs sniffing on the TUN), `time` window, `days`, and `notDomain`/`notIp`/`notPort`; actions proxy/direct/block;
  `domainStrategy`: asis | ipifnonmatch | ipondemand; `list:NAME`, `geoip:XX` and `geosite:XX` entries filled by `mobile.SetRouteList(name, "one per line")` (bring your own country lists).
- Split tunneling: `"split": {"mode": "bypass"|"only", "domain": [], "ip": [], "port": ""}`; one-switch options `bypassLan`, `blockQuic`, `blockBittorrent`.
  Per-app split tunneling is done by the Android VpnService (`addAllowedApplication` / `addDisallowedApplication`).
- Live changes: `mobile.UpdateRouting(json)` swaps the rules without reconnecting and `mobile.SetRouteLists(json)` loads several lists with one rebuild. Start with a `routing` section (it may be `{}`) to use them.
- Debugging: `mobile.ExplainRoute("tcp", "host:443", "")` returns `{"action":"direct","rule":"builtin:lan-ip"}`.
- Mux.Cool (`mux: {enabled, concurrency}`) for VLESS/VMess/Trojan/Shadowsocks, TCP + UDP sessions.
- BadVPN udpgw (`udpgw: "127.0.0.1:7300"`): UDP over the SSH (or any) connection when the protocol has no native UDP.
- `directDns` (default 1.1.1.1:53): protected resolver so hostnames (including your server's) never loop into the VPN.
- `mobile.StartTunEx(json, fd, mtu, dns, fakeDNS, sniff)`: fake-IP DNS + SNI/Host sniffing so domain and protocol rules work on TUN traffic.

Example routing:
```json
{"default":"proxy","domainStrategy":"ipifnonmatch","bypassLan":true,
 "rules":[{"action":"block","domain":["keyword:ads."]},{"action":"direct","domain":["list:local-sites"]}]}
```

<img src="docs/assets/divider.svg" alt="" width="100%">

## 📱 TUN (Android)
1. `go get gvisor.dev/gvisor@go && go mod tidy`
2. In VpnService: `mobile.SetProtector { protect(it) }`, resolve the server hostname to an IP *before* establishing the VPN,
   then `mobile.StartTun(json, pfd.detachFd().toLong(), 1500, "1.1.1.1:53")`.
3. TCP, DNS and UDP are carried (UDP needs a protocol with native UDP, or `udpgw`). IPv4 only: IPv6 packets are not carried through the TUN yet, so route `::/0` into the VPN interface and let it drop (as the app does) rather than leave IPv6 outside the tunnel.

<img src="docs/assets/divider.svg" alt="" width="100%">

## 💻 Command line
`cmd/v2tun` is a small CLI that runs in Termux, so a config can be tried on the phone without building the app.

```text
v2tun run       -c config.json [-l 127.0.0.1:10808] [-user U -pass P]   local SOCKS5 (CONNECT and UDP ASSOCIATE)
v2tun link      <share link>                                            print the JSON config of a share link
v2tun validate  -c config.json                                          check a config without connecting
v2tun payload   -c config.json                                          show what the payload would send
v2tun ping      -c config.json [-url URL]                               time to a first response
v2tun speed     -c config.json [-url URL] [-t 10]                       download speed through the tunnel
v2tun scan      -c config.json -hosts file [-field payload.host] [-j 3] [-t 15]   find hosts a network lets through
```

A config file of `-` is read from standard input. `scan` replaces one field (`payload.host`, `tls.sni`, `ws.host`, `payload.proxy` or `server`) with each line of the hosts file and reports which ones work, fastest first.

> [!CAUTION]
> Without `-user` and `-pass`, every app on the device that can reach the listener can use your tunnel. Keep it on `127.0.0.1` or set a password.

<img src="docs/assets/divider.svg" alt="" width="100%">

## 📲 App API (gomobile)
All functions live in package `mobile` and take strings and numbers only.

| area | functions |
| --- | --- |
| run | `Start`, `StartEx` (SOCKS5 with optional auth), `Stop`, `StartTun`, `StartTunEx`, `StopTun`, `SetProtector` |
| configs and links | `ParseLink`, `Validate`, `Probe`, `Ping`, `SpeedTest`, `ScanHosts` |
| payload | `ValidatePayload`, `PreviewPayload`, `PayloadPreview` |
| routing | `SetRouteList`, `SetRouteLists`, `UpdateRouting`, `ExplainRoute` |
| state | `ActiveOutbound`, `TrafficUp`, `TrafficDown`, `ResetTraffic` |

`ValidatePayload` and `PreviewPayload` compile templates the way the tunnel does, so HTTP Injector spellings such as `[ssh]` and `[b64=random16]` preview as they will be sent.

<img src="docs/assets/divider.svg" alt="" width="100%">

## 🛠️ Development
CI runs `go build`, `go vet` and `go test -race` on every push to `main` and `fix/**` and on pull requests, and uploads the resolved `go.mod` / `go.sum`.
Commit the `go.sum` from that artifact (or from a local `go mod tidy`) so builds use pinned dependency versions.

What is planned, and what needs a live server to verify: see the **[Roadmap](ROADMAP.md)**.
