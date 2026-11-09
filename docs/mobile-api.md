# Mobile API notes

## Local SOCKS5 server

`mobile.Start(json, "127.0.0.1:10808")` serves SOCKS5 CONNECT and UDP ASSOCIATE through the tunnel.
`mobile.StartEx(json, addr, username, password)` adds RFC 1929 authentication. Set a password whenever other apps on the
device could reach the listener; without one, any of them can use your tunnel.

UDP ASSOCIATE relays datagrams from the client that opened the association through the same routing rules as everything
else (so `blockQuic`, direct/proxy rules and udpgw apply). The association ends when the TCP control connection closes.

## Change routing while connected

The config you start with must contain a `"routing"` section (it may be `{}`); then:

- `mobile.UpdateRouting(routingJSON)` swaps rules, split tunneling and the switches without reconnecting. A bad config is
  rejected and the old rules stay active.
- `mobile.SetRouteList(name, "one per line")` / `mobile.SetRouteLists(json)` supply `list:NAME`, `geoip:XX`, `geosite:XX`
  entries. `{"geoip:cn": ["1.0.1.0/24", "..."], "geosite:ads": ["domain:tracker.example", "keyword:doubleclick"]}`
- `mobile.ExplainRoute("tcp", "example.com:443", "tls")` returns `{"action":"direct","rule":"builtin:lan-ip"}`, handy for a
  "why was this routed like that" screen. Rule names are the rule's `name`, `rule#N`, `builtin:*`, `split:*` or `default`.

Rules that list domains or IPs but have no entries yet (a list that was not supplied) never match, so a missing list can
not turn `direct` into "send everything outside the VPN".

## Split tunneling

By destination (library):

```json
"routing": {"split": {"mode": "bypass", "domain": ["domain:bank.example"], "ip": ["203.0.113.0/24"], "port": ""}}
```

- `bypass`: the listed traffic goes direct, everything else through the tunnel.
- `only`: only the listed traffic goes through the tunnel, everything else goes direct.
- `bypassLan`, `blockQuic`, `blockBittorrent` are single switches; BitTorrent detection needs `sniff` on `StartTunEx`.

By app (Android, in your VpnService before `establish()`):

```kotlin
val b = Builder()
// only these apps use the VPN ...
for (pkg in selected) b.addAllowedApplication(pkg)
// ... or: everything except these apps
// for (pkg in excluded) b.addDisallowedApplication(pkg)
```

Use one of the two, not both. Add your own app (`packageName`) to the disallowed list or leave it out of the allowed list;
the tunnel's own sockets are already exempt through `SetProtector`.

## Payload helpers

- `mobile.ValidatePayload(template)` returns an error for a template that does not compile.
- `mobile.PreviewPayload(template, host, server, port)` renders it with visible `\r\n` and `--- split ---` / `--- wait Nms ---`
  markers, so users can check a payload before connecting.

The tag list is at the top of `payload/payload.go`. Notes on the less obvious ones: `[netData]`, `[raw]` and `[realData]`
all render the request line `<method|CONNECT> host:port HTTP/1.1`; `[crlf*2]` repeats; tags nest (`[b64=[host]:[port]]`);
`[delay_split=300]` splits and waits 300 ms; `\[` and `\]` write literal brackets.
