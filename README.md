# v2-tun

Xray-free tunnel library in Go. Module/namespace: `io.surprise.vpn`.

Chain: tcp -> [payload pre-tls] -> tls or reality (SNI, ALPN, uTLS fingerprint) -> [payload post-tls] -> ws / httpupgrade / h2 / grpc / xhttp -> protocol.

Protocols: trojan, vless, vmess (AEAD + legacy alterId>0, plaintext ok), shadowsocks (AEAD + legacy stream), ssh
(max-compat algorithm lists by default; override via `advanced`), socks5 (user/password), socks4/4a, http and https proxies (CONNECT, Basic auth),
hysteria 2 and hysteria 1.

Local proxy: `mobile.Start(json, "127.0.0.1:10808")` runs SOCKS5 through the tunnel (feed it to tun2socks for TUN mode).

Build: `go mod tidy && go vet ./... && go test ./...`
Android: `gomobile bind -target=android -javapkg=io.surprise -o v2tun.aar io.surprise.vpn/mobile`

## Protocols
| `protocol` | Notes |
| --- | --- |
| `vless`, `vmess`, `trojan`, `shadowsocks` | TCP and UDP, Mux.Cool, any transport below |
| `ssh` | direct-tcpip; UDP through udpgw. TLS is optional, see SSH over WebSocket |
| `socks5` (`socks`) | CONNECT, optional username/password; UDP through udpgw |
| `socks4` (`socks4a`) | CONNECT; the user id is `username`; host names use SOCKS4a |
| `http` / `https` | CONNECT with Basic auth (`username`/`password`) and extra headers (`proxyHeaders`); `https` needs `tls.enabled` |
| `hysteria2` (`hy2`) | QUIC, TCP and UDP, Salamander obfs, certificate pinning |
| `hysteria` (`hy`) | Hysteria 1 (protocol v3), TCP and UDP, xplus obfs |

Socks and http proxies take the whole chain underneath them, so a payload, TLS with a fake SNI or a WebSocket can sit between you and the proxy.
Share links: `socks5://user:pass@host:1080`, `socks4://host:1080`, `http://user:pass@host:8080`, `https://host:443`, `hysteria2://..`, `hysteria://..`.

## SSH over WebSocket (payload, no TLS needed)
The usual injector setup is host:port, username, password, a payload and optionally an HTTP proxy. TLS is the user's choice (`tls.enabled`), never required:
```json
{"protocol":"ssh","server":"ssh.example.com","port":80,"username":"user","password":"pass",
 "payload":{"template":"@ssh-ws","host":"bug.example.com"}}
```
The `@ssh-ws` preset is `GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]`. The server answers `101 Switching Protocols` and then carries the raw SSH stream (no WebSocket framing), so the reply is read and dropped before SSH starts. That happens automatically for an HTTP-looking payload on a plain tcp stream; set `expectResponse` to `true` or `false` to override.

Through an HTTP proxy (remote proxy mode), the TCP connection goes to the proxy and the payload names your real server in `[host_port]`:
```json
{"protocol":"ssh","server":"ssh.example.com","port":22,"username":"user","password":"pass",
 "payload":{"template":"CONNECT [host_port] HTTP/1.1[crlf][crlf]GET / HTTP/1.1[crlf]Host: bug.example.com[crlf]Upgrade: websocket[crlf][crlf]","proxy":"1.2.3.4:8080"}}
```
One reply is read per HTTP request line in the payload (here two: the proxy's 200, then the server's 101); `expectResponses` overrides the count. Leave `host` empty when the template uses `[host_port]` for the real server, and write the bug host into the template.

### Response changer
`responseMap` changes the status the payload layer sees before it decides whether the reply is acceptable. Keys are a status code or a class, values are the code to treat it as:
```json
"payload": {"template": "@ssh-ws", "responseMap": {"301": 200, "3xx": 200}}
```
Without a map, `101` and any `2xx` are accepted; `expectCodes` replaces that list (`0` accepts anything). With the map above a `301 Moved Permanently` works like `200 OK`; exact codes win over classes. Only the status line and headers of a reply are read, so a server that sends a body with its fake status should be avoided. The map applies to the payload layer, not to the http/https proxy protocol.

## Hysteria
```json
{"protocol":"hysteria2","server":"example.com","port":443,"password":"secret",
 "tls":{"sni":"example.com","allowInsecure":false},
 "hysteria":{"obfs":"salamander-password","pinSha256":""}}
```
- **Hysteria 2**: `password` is the auth string, `hysteria.obfs` the Salamander password, `hysteria.pinSha256` pins the server certificate (replaces CA checks), `hysteria.downMbps` advertises your receive rate (0 lets the server decide). Port hopping is not supported.
- **Hysteria 1**: `password` is the auth string, `hysteria.obfs` the xplus password, `hysteria.alpn` defaults to `hysteria`. `upMbps` (default 10) and `downMbps` (default 50) are required by the server, and **the server sends at the `downMbps` you declare**, so set it to what your link can take. faketcp and wechat-video are not supported.
- Both run over one QUIC connection that is re-opened when it dies. TCP is a stream per connection and UDP rides on QUIC datagrams (fragmented when needed). They bring their own QUIC/TLS: `payload`, `reality`, `fragment` and other transports are rejected for them.
- There is no Brutal congestion control in the client (quic-go has no hook for it), so uploads use quic-go's default.
- Links: `hysteria2://auth@host:443/?sni=..&insecure=1&obfs=salamander&obfs-password=..&pinSHA256=..` and `hysteria://host:443?auth=..&peer=..&insecure=1&upmbps=..&downmbps=..&alpn=..&obfs=xplus&obfsParam=..`.
- Written from the published protocol specs and checked against loopback tests only. Try it against your own server before relying on it.

## Transports
tcp, ws, httpupgrade, h2 (http), grpc (gun, no grpc lib), quic (single stream), xhttp. TLS: allowInsecure, SNI, ALPN, uTLS fingerprints.
Not yet: mKCP, the REALITY spiderX crawl, XTLS Vision flow.

## Payload (HTTP Injector style)
`"payload": {"template": "@connect", "host": "bug.example.com", "stage": "pre-tls", "expectResponse": true, "expectResponses": 1, "expectCodes": [200], "responseMap": {"301": 200}, "vars": {"token": "abc"}, "proxy": "1.2.3.4:8080"}`
- `template`: any template (tags are listed at the top of `payload/payload.go`: `[crlf]`, `[host_port]`, `[netData]`, `[split]`, `[delay=500]`, `[random=a|b]`, `[rotate=a|b]`, `[var=token]`, `[b64=...]`, `[rand_ua]`, ...; `[ssh]` is `[host_port]` and `[real_raw]` is `[raw]`) or a preset: `@connect`, `@split-connect`, `@get`, `@head`, `@post`, `@websocket`, `@ssh-ws`.
- `stage`: `pre-tls` (default) sends the payload right after the TCP connect; `post-tls` sends it inside TLS.
- `proxy`: remote proxy mode (see above). Pre-tls only.
- `expectResponse`, `expectResponses`, `expectCodes`, `responseMap`: how the server's HTTP reply is handled (see above).
- `host`, `method`, `userAgent`, `vars` fill `[host]`, `[method]`, `[ua]` and `[var=name]`; `[sni]` takes the TLS/REALITY server name.

## REALITY
Set `"reality": {"publicKey": "<pbk>", "shortId": "<sid hex>", "serverName": "<cover site>", "fingerprint": "chrome"}`
(it replaces the `tls` layer; it works with tcp, h2, grpc and xhttp, not quic). Share links with `security=reality&pbk=..&sid=..&sni=..&fp=..`
are parsed by `ParseLink`. Links that carry `flow=xtls-rprx-vision` are rejected because Vision is not implemented; use a server inbound
without a flow. A wrong key, shortId or server name fails with a clear error instead of hanging. Test it against your own server before relying on it.

## TUN (Android)
1. `go get gvisor.dev/gvisor@go && go mod tidy`
2. In VpnService: `mobile.SetProtector { protect(it) }`, resolve the server hostname to an IP *before* establishing the VPN,
   then `mobile.StartTun(json, pfd.detachFd().toLong(), 1500, "1.1.1.1:53")`.
3. TCP, DNS and UDP are carried (UDP needs a protocol with native UDP, or `udpgw`).

## Added in round 3
- UDP relay: VLESS (cmd 2), VMess (cmd 2), Trojan (UDP ASSOCIATE), Shadowsocks (native UDP), Hysteria 1 and 2. TUN forwards all UDP through it; SSH, SOCKS and HTTP proxies have no UDP (use `udpgw`).
- XHTTP/SplitHTTP: `network: "xhttp"`, `xhttpMode`: auto|packet-up|stream-up|stream-one, tuning via `xhttp: {xPaddingBytes, scMaxEachPostBytes, scMinPostsIntervalMs}`. Verify against your Xray version.
- TLS fragmenting: `"fragment": {"length":[10,40], "interval":[5,20]}`.
- Share links: `mobile.ParseLink(link)` -> JSON config (vless, vmess, trojan, ss, ssh, socks, http, hysteria).
- `mobile.Ping`, `mobile.TrafficUp/Down`.

## Round 4: routing, mux, BadVPN
- Routing (`routing`): rules with domain (`full:`, `domain:`, `keyword:`, `regexp:`, `dotless:`), ip (CIDR, `geoip:private`), port, network, sniffed `protocol`
  (http, tls, bittorrent, ssh; needs sniffing on the TUN), `time` window, `days`, and `notDomain`/`notIp`/`notPort`; actions proxy/direct/block;
  `domainStrategy`: asis | ipifnonmatch | ipondemand; `list:NAME`, `geoip:XX` and `geosite:XX` entries filled by `mobile.SetRouteList(name, "one per line")` (bring your own country lists).
- Split tunneling: `"split": {"mode": "bypass"|"only", "domain": [], "ip": [], "port": ""}`; one-switch options `bypassLan`, `blockQuic`, `blockBittorrent`.
  Per-app split tunneling is done by the Android VpnService (`addAllowedApplication` / `addDisallowedApplication`).
- Mux.Cool (`mux: {enabled, concurrency}`) for VLESS/VMess/Trojan/Shadowsocks, TCP + UDP sessions.
- BadVPN udpgw (`udpgw: "127.0.0.1:7300"`): UDP over the SSH (or any) connection when the protocol has no native UDP.
- `directDns` (default 1.1.1.1:53): protected resolver so hostnames (including your server's) never loop into the VPN.
- `mobile.StartTunEx(json, fd, mtu, dns, fakeDNS, sniff)`: fake-IP DNS + SNI/Host sniffing so domain and protocol rules work on TUN traffic.
Example routing: {"default":"proxy","domainStrategy":"ipifnonmatch","bypassLan":true,"rules":[{"action":"block","domain":["keyword:ads."]},{"action":"direct","domain":["list:local-sites"]}]}

## Development
CI runs `go build`, `go vet` and `go test -race` on every push to `main` and `fix/**` and on pull requests, and uploads the resolved `go.mod` / `go.sum`.
Commit the `go.sum` from that artifact (or from a local `go mod tidy`) so builds use pinned dependency versions.
