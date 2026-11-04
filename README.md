# v2-tun

Xray-free tunnel library in Go. Module/namespace: `io.surprise.vpn`.

Chain: tcp -> [payload pre-tls] -> tls (allowInsecure, SNI, ALPN) -> [payload post-tls] -> ws / httpupgrade -> protocol.

Protocols: trojan, vless, vmess (AEAD + legacy alterId>0, plaintext ok), shadowsocks (AEAD + legacy stream), ssh
(max-compat algorithm lists by default; override via `advanced`).

Local proxy: `mobile.Start(json, "127.0.0.1:10808")` runs SOCKS5 through the tunnel (feed it to tun2socks for TUN mode).

Build: `go mod tidy && go vet ./... && go test ./...`
Android: `gomobile bind -target=android -javapkg=io.surprise -o v2tun.aar io.surprise.vpn/mobile`

## Transports
tcp, ws, httpupgrade, h2 (http), grpc (gun, no grpc lib), quic (single stream). TLS: allowInsecure, SNI, ALPN, uTLS fingerprints.
Not yet: mKCP, XHTTP/SplitHTTP, Reality, UDP relay.

## TUN (Android)
1. `go get gvisor.dev/gvisor@go && go mod tidy`
2. In VpnService: `mobile.SetProtector { protect(it) }`, resolve the server hostname to an IP *before* establishing the VPN,
   then `mobile.StartTun(json, pfd.detachFd().toLong(), 1500, "1.1.1.1:53")`.
3. TCP and DNS are carried; other UDP is dropped until UDP relay lands.

## Added in round 3
- UDP relay: VLESS (cmd 2), VMess (cmd 2), Trojan (UDP ASSOCIATE), Shadowsocks (native UDP). TUN forwards all UDP through it; SSH has no UDP.
- XHTTP/SplitHTTP: `network: "xhttp"`, `xhttpMode`: auto|packet-up|stream-one (h2 only; verify against your Xray version).
- TLS fragmenting: `"fragment": {"length":[10,40], "interval":[5,20]}`.
- Share links: `mobile.ParseLink(link)` -> JSON config (vless, vmess, trojan, ss, ssh).
- `mobile.Ping`, `mobile.TrafficUp/Down`.

## Round 4: routing, mux, BadVPN
- Routing (`routing`): rules with domain (`full:`, `domain:`, `keyword:`, `regexp:`), ip (CIDR, `geoip:private`), port, network; actions proxy/direct/block;
  `domainStrategy: "ipifnonmatch"`; `list:NAME` entries filled by `mobile.SetRouteList(name, "one per line")` (bring your own country lists).
- Mux.Cool (`mux: {enabled, concurrency}`) for VLESS/VMess/Trojan/Shadowsocks, TCP + UDP sessions.
- BadVPN udpgw (`udpgw: "127.0.0.1:7300"`): UDP over the SSH (or any) connection when the protocol has no native UDP.
- `directDns` (default 1.1.1.1:53): protected resolver so hostnames (including your server's) never loop into the VPN.
- `mobile.StartTunEx(json, fd, mtu, dns, fakeDNS, sniff)`: fake-IP DNS + SNI/Host sniffing so domain rules work on TUN traffic.
Example routing: {"default":"proxy","domainStrategy":"ipifnonmatch","rules":[{"action":"direct","ip":["geoip:private"]},{"action":"block","domain":["keyword:ads."]},{"action":"direct","domain":["list:local-sites"]}]}
