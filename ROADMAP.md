<div align="center">

<img src="docs/assets/roadmap.svg" alt="v2-tun roadmap: what ships next" width="100%">

![shipped](https://img.shields.io/badge/✅-shipped-34d399?style=for-the-badge&labelColor=0b1020)
![planned](https://img.shields.io/badge/📋-planned-22d3ee?style=for-the-badge&labelColor=0b1020)
![live server](https://img.shields.io/badge/🧪-needs%20a%20live%20server-a78bfa?style=for-the-badge&labelColor=0b1020)

</div>

<img src="docs/assets/divider.svg" alt="" width="100%">

Everything under **Shipped** is described in the [README](README.md) and works as written there. Nothing under the other headings exists yet.

## ✅ Shipped
- **Protocols**: trojan, vless, vmess, shadowsocks, ssh, socks4/5, http/https proxies, Hysteria 1 and 2
- **XTLS Vision** for vless (record layer, `checkFlow` validation); still untested against a live server, see below
- **Transports**: tcp, ws, httpupgrade, h2, grpc, quic, **xhttp** (auto, packet-up, stream-up, stream-one), REALITY, TLS fragmenting
- **Payload engine**: HTTP Injector style tags and presets, `@ssh-ws`, `@ssh-ws/tcp`, response changer, remote proxy mode
- **SSH extras**: double hop (`sshNext`), host key pinning
- **Reliability**: failover with `backups`, latency sort, WebSocket ping, idle timeout
- **Routing**: rules, split tunneling, geoip/geosite lists, live `UpdateRouting`, `ExplainRoute`
- **UDP**: native relay per protocol, udpgw, SOCKS5 UDP ASSOCIATE (also in the CLI `run` command)
- **Tools**: `v2tun` CLI (run, link, validate, payload, ping, speed, scan), `Validate`, `SpeedTest`, `ScanHosts`

<img src="docs/assets/divider.svg" alt="" width="100%">

## 🧪 Needs a real server or CI to do properly
- **Interop tests in CI**: run the library against OpenSSH, Xray, a Hysteria server and a Trojan server in containers. Most protocol code was written from specs and is only tested against fakes written by the same author. This is also the only way to confirm **Vision**, **REALITY** and **XHTTP** against real inbounds. (A workflow file has to be added by hand: the GitHub connector cannot create workflows.)

## 📋 Next up (ideas, roughly in this order)
- **Reconnect on network change**: a `mobile.NetworkChanged()` call that drops dead sessions and redials when wifi and mobile data swap, plus a kill switch (the other half is the Android VpnService side)
- **Scan results into the config**: turn the best `scan` results into `backups` or a `[rotate=...]` list so one run produces a self-healing config
- **Log callback** with levels and secret redaction, so the app's Logs tab has something safe to show
- **DNS over HTTPS / TLS** for `directDns`, and DNS leak protection
- **Subscription import**: fetch a subscription URL, parse every link with `ParseLink`, read traffic and expiry headers

## 📋 Protocols
- AnyTLS, TUIC v5, WireGuard (userspace, through the gVisor stack)
- Shadowsocks 2022, simple-obfs (http/tls), ShadowTLS v3, mKCP
- Hysteria port hopping, faketcp and wechat-video; Brutal congestion control
- DNSTT / SlowDNS
- REALITY spiderX crawl

## 📋 Network and privacy
- Encrypted Client Hello (ECH)
- IPv6 through the TUN

## 📋 App-facing
- Local SOCKS/HTTP proxy with a password for hotspot sharing (SOCKS5 with a password already exists; an HTTP listener does not)
- Per-domain / per-app traffic stats, per-outbound latency metrics
- JSON schema for the config, encrypted/expiring config export

## 📋 Performance
- Buffer pools and connection pre-warming (several SSH sessions, QUIC 0-RTT)

<img src="docs/assets/divider.svg" alt="" width="100%">

Have a use case that is not here? Open an issue with the network you are on and what you tried.
