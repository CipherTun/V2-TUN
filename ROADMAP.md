# Roadmap

What is not in the library yet, roughly in the order I would do it. Everything
that is listed in the README works as described there; nothing here exists.

## Needs a real server or CI to do properly
- **Interop tests in CI**: run the library against OpenSSH, Xray, a Hysteria
  server and a Trojan server in containers. Most protocol code was written from
  specs and is only tested against fakes written by the same author. (A workflow
  file has to be added by hand: the GitHub connector cannot create workflows.)

## Protocols
- TUIC v5, WireGuard (userspace, through the gVisor stack)
- VLESS Vision flow (makes most public REALITY links usable)
- Shadowsocks 2022, simple-obfs (http/tls), ShadowTLS v3, mKCP
- Hysteria port hopping, faketcp and wechat-video; Brutal congestion control
- DNSTT / SlowDNS

## Network and privacy
- DNS over HTTPS / TLS for `directDns`, DNS leak protection
- Encrypted Client Hello (ECH)
- IPv6 through the TUN

## App-facing
- Reconnect on network change and a kill switch (mostly the Android VpnService side)
- Local SOCKS/HTTP proxy with a password, for hotspot sharing
- Per-domain / per-app traffic stats, per-outbound latency metrics
- Log callback with levels and secret redaction
- JSON schema for the config, encrypted/expiring config export
- Rotation lists for SNI and payloads (fallbacks cover the manual case)

## Performance
- Buffer pools and connection pre-warming (several SSH sessions, QUIC 0-RTT)
