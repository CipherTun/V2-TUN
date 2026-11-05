# v2-tun

Xray-free tunnel library in Go. Module/namespace: `io.surprise.vpn`.

Chain: tcp -> [payload pre-tls] -> tls or reality (SNI, ALPN, uTLS fingerprint) -> [payload post-tls] -> ws / httpupgrade / h2 / grpc / xhttp -> protocol.

Protocols: trojan, vless, vmess (AEAD + legacy alterId>0, plaintext ok), shadowsocks (AEAD + legacy stream), ssh
(max-compat algorithm lists by default; override via `advanced`).

Local proxy: `mobile.Start(json, "127.0.0.1:10808")` runs SOCKS5 through the tunnel (feed it to tun2socks for TUN mode).

Build: `go mod tidy && go vet ./... && go test ./...`
Android: `gomobile bind -target=android -javapkg=io.surprise -o v2tun.aar io.surprise.vpn/mobile`

## Transports
tcp, ws, httpupgrade, h2 (http), grpc (gun, no grpc lib), quic (single stream), xhttp. TLS: allowInsecure, SNI, ALPN, uTLS fingerprints.
Not yet: mKCP, the REALITY spiderX crawl, XTLS Vision flow.

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
- UDP relay: VLESS (cmd 2), VMess (cmd 2), Trojan (UDP ASSOCIATE), Shadowsocks (native UDP). TUN forwards all UDP through it; SSH has no UDP.
- XHTTP/SplitHTTP: `network: "xhttp"`, `xhttpMode`: auto|packet-up|stream-up|stream-one, tuning via `xhttp: {xPaddingBytes, scMaxEachPostBytes, scMinPostsIntervalMs}`. Verify against your Xray version.
- TLS fragmenting: `"fragment": {"length":[10,40], "interval":[5,20]}`.
- Share links: `mobile.ParseLink(link)` -> JSON config (vless, vmess, trojan, ss, ssh).
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
- Payload templates also support `[sni]`, `[var]` and `[ip]` values.
Example routing: {"default":"proxy","domainStrategy":"ipifnonmatch","bypassLan":true,"rules":[{"action":"block","domain":["keyword:ads."]},{"action":"direct","domain":["list:local-sites"]}]}

## Development
CI runs `go build`, `go vet` and `go test -race` on every push to `main` and `fix/**` and on pull requests, and uploads the resolved `go.mod` / `go.sum`.
Commit the `go.sum` from that artifact (or from a local `go mod tidy`) so builds use pinned dependency versions.
