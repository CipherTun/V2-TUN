# Command line and tools

Everything here runs without the Android app, so a config can be tried on the
phone in Termux (`pkg install golang git`, then `go build ./cmd/v2tun`).

```
v2tun run      -c config.json [-l 127.0.0.1:10808]   local SOCKS5 proxy through the config
v2tun link     'vless://...'                         print the JSON config of a share link
v2tun validate -c config.json                        check a config without connecting
v2tun payload  -c config.json                        show what the payload would send
v2tun ping     -c config.json [-url URL]             time to a first response through the tunnel
v2tun speed    -c config.json [-url URL] [-t 10]     download speed through the tunnel
v2tun scan     -c config.json -hosts hosts.txt       find which hosts a network lets through
```

## Backups (auto-failover)
`backups` is a list of complete alternative configs. When a connection fails
through the main config, they are tried in order, each attempt limited to
`failoverTimeoutSec` seconds (default 12); the one that worked last is tried
first next time. Use it for a second server, another bug host or payload, or
another protocol:
```json
{"protocol":"ssh","server":"a.example.com","port":80,"username":"u","password":"p",
 "payload":{"template":"@ssh-ws","host":"bug1.example.com"},
 "failoverTimeoutSec":10,
 "backups":[
   {"protocol":"ssh","server":"a.example.com","port":80,"username":"u","password":"p","payload":{"template":"@ssh-ws","host":"bug2.example.com"}},
   {"protocol":"hysteria2","server":"b.example.com","port":443,"password":"secret"}
 ]}
```
`routing`, `udpgw` and `directDns` belong to the top-level config only: a backup
that sets any of them is rejected, and so is a backup with backups of its own
(list every backup in the top-level `backups`). `mobile.ActiveOutbound()` (0 =
main config, 1 = first backup, ..., -1 when nothing is running) tells which one
is in use. UDP uses the first outbound that can relay it, and falls back to
`udpgw` when none can.

## Scanning for a working bug host
`scan` and `mobile.ScanHosts` copy the config once per value of a field
(`payload.host`, `tls.sni`, `ws.host`, `payload.proxy` or `server`), probe each
copy a few at a time, and report which ones work and how fast. Give a URL as the
target to prove that data flows; a `host:port` only proves that the tunnel comes
up (payload accepted, login done). Keep the number of parallel probes low for SSH
servers that rate-limit logins.

## Payload preview
`v2tun payload` and `mobile.PayloadPreview` render the payload of a config
exactly as it would be sent: where the TCP connection goes, each segment with its
escapes visible and the pause after it, and whether and how the HTTP replies are
checked (count, accepted codes, response changer). Nothing is sent.
`mobile.PreviewPayload(template, host, port)` renders just a template, without a
config.

## SSH host-key pinning
`advanced.sshHostKey` pins the SSH server's key: an OpenSSH fingerprint
(`SHA256:...`, from `ssh-keygen -l -f key.pub`) or 64 hex characters. Without it
any server key is accepted, like in most tunnel apps. A wrong key refuses the
connection.

## For the app
`mobile.Validate(json)` returns an empty string for a valid config and the reason
otherwise. `mobile.SpeedTest(json, url, seconds)` returns `{"bytes":..,"bps":..}`.
`mobile.ScanHosts(json, field, values, target, concurrency, seconds)` returns a
JSON array of `{value, ok, ms, error}`.

## Fuzzing
`go test -fuzz=FuzzParseLink .`, `go test -fuzz=FuzzCompile ./payload` and
`go test -fuzz=FuzzSniff ./tun` look for inputs that make the parsers panic. A
plain `go test` runs only the seed inputs.
