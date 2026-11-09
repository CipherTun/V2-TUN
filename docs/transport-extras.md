# Transport extras

All of these are optional and off by default. A config that does not mention
them behaves exactly as before.

## SSH double hop: `advanced.sshNext`

The top-level `server`, `port`, `username`, `password`, `privateKey` and
`advanced.sshHostKey` describe the **first (jump) host**. It is reached through
the whole dial chain (payload, TLS/SNI, WebSocket, ...), so the network only
sees that first hop. `advanced.sshNext` is the **second host**, reached from
inside the jump session; traffic exits there.

```json
{
  "protocol": "ssh",
  "server": "jump.example.com", "port": 443,
  "username": "u1", "password": "p1",
  "payload": {"template": "CONNECT [host_port] HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]", "host": "bug.host.example"},
  "advanced": {
    "sshHostKey": "SHA256:...",
    "sshNext": {
      "server": "target.example.com:22",
      "username": "u2", "password": "p2",
      "hostKey": "SHA256:..."
    }
  }
}
```

`sshNext.server` is `host:port` as the **jump host** reaches it. `hostKey` is a
pin in the same format as `advanced.sshHostKey` (empty accepts any key).

## WebSocket ping: `ws.pingSec`

`"ws": {"pingSec": 20}` sends a masked WebSocket Ping frame every 20 seconds
so carriers and CDNs do not drop an idle tunnel. Only for `network: "ws"`
(not `httpupgrade`, which has no framing). For SSH there is also the SSH-level
keepalive (every 25 s), which is always on.

## Idle timeout: `idleTimeoutSec`

Top level. Closes a tunneled connection after that many seconds without data
in **either** direction. `0` (default) means never. Anything moving in either
direction keeps the connection alive.

## Latency-sorted failover: `latencySortSec`

Top level, used together with `backups`. Every N seconds each server (the
payload `proxy` if there is one, else `server:port`) is probed with a TCP
connect. The outbound in use stays first until it fails; after that the
fastest is tried first and servers that did not answer go last. Hysteria and
QUIC outbounds cannot be probed with TCP and rank between the two groups.
`activeOutbound` still reports the index in the config list.

## Payload aliases

There are no payload presets; write the payload yourself. `[b64=random16]` is
accepted as a spelling of `[ws_key]`, `[ssh]` as `[host_port]` and `[real_raw]`
as `[raw]`.
