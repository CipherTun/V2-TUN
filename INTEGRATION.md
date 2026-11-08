# Wiring multi-stream QUIC and mKCP into `v2tun.go` (branch `fix/review-20261104`)

The transport files (`transport/quic.go`, `transport/kcp.go`, `transport/kcp_test.go`) are
self-contained. `v2tun.go` is NOT changed by these commits; these are the edits to make there.

## 1. Config types (next to `MuxConfig`)

```go
type QUICConfig struct {
	MultiStream  bool `json:"multiStream"` // reuse one QUIC connection, one stream per dial
	KeepAliveSec int  `json:"keepAliveSec"`
	MaxIdleSec   int  `json:"maxIdleSec"`
}

type KCPConfig struct {
	MTU              int    `json:"mtu"`              // default 1350
	TTI              int    `json:"tti"`              // ms, default 50
	UplinkCapacity   int    `json:"uplinkCapacity"`   // MB/s, default 5
	DownlinkCapacity int    `json:"downlinkCapacity"` // MB/s, default 20
	Congestion       bool   `json:"congestion"`
	ReadBufferSize   int    `json:"readBufferSize"`   // MB, default 2
	WriteBufferSize  int    `json:"writeBufferSize"`  // MB, default 2
	Header           string `json:"header"`           // none|srtp|utp|wechat-video|dtls|wireguard
	Seed             string `json:"seed"`             // empty = classic auth, set = AES-GCM
}
```

## 2. Two fields in `Config`

```go
	QUIC *QUICConfig `json:"quic,omitempty"`
	KCP  *KCPConfig  `json:"kcp,omitempty"`
```

## 3. `buildOutbound`

Replace the bare `case "quic":` in the transport switch with:

```go
	case "quic", "kcp", "mkcp":
```

and extend the REALITY guard so it also rejects the UDP transports:

```go
	if cfg.Reality != nil && (net_ == "quic" || net_ == "kcp" || net_ == "mkcp") {
		return nil, 0, errors.New("v2tun: reality cannot be combined with the quic or kcp transport")
	}
```

## 4. `baseChain`

Replace the `if net_ == "quic" { ... }` block with:

```go
	switch net_ {
	case "quic":
		q := &transport.QUIC{ServerName: cfg.TLS.SNI, ALPN: cfg.TLS.ALPN, AllowInsecure: cfg.TLS.AllowInsecure, Resolver: res}
		if c := cfg.QUIC; c != nil {
			q.MultiStream = c.MultiStream
			q.KeepAlive = time.Duration(c.KeepAliveSec) * time.Second
			q.MaxIdle = time.Duration(c.MaxIdleSec) * time.Second
		}
		return q, nil
	case "kcp", "mkcp": // UDP transport: the TLS, payload and fragment layers do not apply
		k := &transport.KCP{Resolver: res}
		if c := cfg.KCP; c != nil {
			k.MTU, k.TTI = c.MTU, c.TTI
			k.UplinkCapacity, k.DownlinkCapacity = c.UplinkCapacity, c.DownlinkCapacity
			k.Congestion = c.Congestion
			k.ReadBufferSize, k.WriteBufferSize = c.ReadBufferSize, c.WriteBufferSize
			k.Header, k.Seed = c.Header, c.Seed
		}
		return k, nil
	}
```

Optional: in `checkTLSVerify`, turn `strings.EqualFold(cfg.Network, "quic")` into a check that
also covers `kcp` / `mkcp`, so a pin that would be ignored is rejected.

## Example configs

```json
{"protocol":"vless","network":"quic","server":"example.com","port":443,"uuid":"...",
 "tls":{"sni":"example.com","alpn":["h3"]},
 "quic":{"multiStream":true}}

{"protocol":"vmess","network":"kcp","server":"1.2.3.4","port":4000,"uuid":"...",
 "kcp":{"header":"wechat-video","seed":"mypassword","tti":20}}
```

Then: `go vet ./... && go test ./transport/`

Notes: mKCP follows the classic v2ray/Xray wire format and is untested against a real server;
set the same `header` and `seed` on both ends. Newer `finalmask` mKCP variants are not covered.
