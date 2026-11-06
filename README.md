# v2-tun

Xray-free tunnel library in Go. Module/namespace: `io.surprise.vpn`.

Chain: tcp -> [payload pre-tls] -> tls or reality (SNI, ALPN, uTLS fingerprint) -> [payload post-tls] -> ws / httpupgrade / h2 / grpc / xhttp -> protocol.

Protocols: trojan, vless, vmess (AEAD + legacy alterId>0, plaintext ok), shadowsocks (AEAD + legacy stream), ssh
(max-compat algorithm lists by default; override via `advanced`), socks5 (user/password), socks4/4a, http and https proxies (CONNECT, Basic auth).

Local proxy: `mobile.Start(json, "127.0.0.1:10808")` runs SOCKS5 through the tunnel (feed it to tun2socks for TUN mode).

Build: `go mod tidy && go vet ./... && go test ./...`
Android: `gomobile bind -target=android -javapkg=io.surprise -o v2tun.aar io.surprise.vpn/mobile`

## Protocols
| `protocol` | Notes |
| --- | --- |
| `vless`, `vmess`, `trojan`, `shadowsocks` | TCP and UDP, Mux.Cool, any transport below |
| `ssh` | direct-tcpip; UDP through udpgw |
| `socks5` (`socks`) | CONNECT, optional username/password; UDP through udpgw |
| `socks4` (`socks4a`) | CONNECT; the user id is `username`; host names use SOCKS4a |
| `http` / `https` | CONNECT with Basic auth (`username`/`password`) and extra headers (`proxyHeaders`); `https` needs `tls.enabled` |

Socks and http proxies take the whole chain underneath them, so a payload, TLS with a fake SNI or a WebSocket can sit between you and the proxy.
Share links: `socks5://user:pass@host:1080`, `socks4://host:1080`, `http://user:pass@host:8080`, `https://host:443`.

## Transports
tcp, ws, httpupgrade, h2 (http), grpc (gun, no grpc lib), quic (single stream), xhttp. TLS: allowInsecure, SNI, ALPN, uTLS fingerprints.
Not yet: mKCP, the REALITY spiderX crawl.

## Payload (HTTP Injector style)
`"payload": {"template": "@connect", "host": "bug.example.com", "stage": "pre-tls", "expectResponse": true, "expectCodes": [200], "vars": {"token": "abc"}, "proxy": "1.2.3.4:8080"}`
- `template`: any template (tags are listed at the top of `payload/payload.go`: `[crlf]`, `[host_port]`, `[netData]`, `[split]`, `[delay=500]`, `[random=a|b]`, `[rotate=a|b]`, `[var=token]`, `[b64=...]`, `[rand_ua]`, ...) or a preset: `@connect`, `@split-connect`, `@get`, `@head`, `@post`, `@websocket`.
- `stage`: `pre-tls` (default) sends the payload right after the TCP connect; `post-tls` sends it inside TLS.
- `proxy` (remote proxy mode): the TCP connection goes to this HTTP proxy, the payload names your real server in `[host_port]`, and the proxy's reply is checked (`expectResponse` is implied, accepted codes are `expectCodes` or 101/2xx). Pre-tls only. After the proxy says 200, TLS, SSH or any protocol runs through it.
- `host`, `method`, `userAgent`, `vars` fill `[host]`, `[method]`, `[ua]` and `[var=name]`; `[sni]` takes the TLS/REALITY server name.

Example, SSH through an HTTP proxy with a CONNECT payload:
`{"protocol":"ssh","server":"ssh.example.com","port":22,"username":"u","password":"p","payload":{"template":"CONNECT [host_port] [protocol][crlf]Host: bug.example.com[crlf][crlf]","proxy":"1.2.3.4:8080"}}`

## REALITY
Set `"reality": {"publicKey": "<pbk>", "shortId": "<sid hex>", "serverName": "<cover site>", "fingerprint": "chrome"}`
(it replaces the `tls` layer; it works with tcp, h2, grpc and xhttp, not quic). Share links with `security=reality&pbk=..&sid=..&sni=..&fp=..`
are parsed by `ParseLink`. A wrong key, shortId or server name fails with a clear error instead of hanging. Test it against your own server before relying on it.

## XTLS Vision
Set `"flow": "xtls-rprx-vision"` on a `vless` config, or use a share link with `flow=xtls-rprx-vision` (`-udp443` is accepted too). It needs the plain
`tcp` transport with `tls.enabled` or `reality`; `New` and `ParseLink` reject it with ws/h2/grpc/xhttp/quic, without TLS or REALITY, and with `mux`.
The client pads the inner TLS handshake and follows the server's switch to direct copy. It is based on Xray-core's behaviour and has only been
tested against its own framing, not a live server, so try it against your own inbound before relying on it. Other flows are rejected.

## TUN (Android)
1. `go get gvisor.dev/gvisor@go && go mod tidy`
2. In VpnService: `mobile.SetProtector { protect(it) }`, resolve the server hostname to an IP *before* establishing the VPN,
   then `mobile.StartTun(json, pfd.detachFd().toLong(), 1500, "1.1.1.1:53")`.
3. TCP, DNS and UDP are carried (UDP needs a protocol with native UDP, or `udpgw`).

## Added in round 3
- UDP relay: VLESS (cmd 2), VMess (cmd 2), Trojan (UDP ASSOCIATE), Shadowsocks (native UDP). TUN forwards all UDP through it; SSH, SOCKS and HTTP proxies have no UDP (use `udpgw`).
- XHTTP/SplitHTTP: `network: "xhttp"`, `xhttpMode`: auto|packet-up|stream-up|stream-one, tuning via `xhttp: {xPaddingBytes, scMaxEachPostBytes, scMinPostsIntervalMs}`. Verify against your Xray version.
- TLS fragmenting: `"fragment": {"length":[10,40], "interval":[5,20]}`.
- Share links: `mobile.ParseLink(link)` -> JSON config (vless, vmess, trojan, ss, ssh, socks, http).
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
