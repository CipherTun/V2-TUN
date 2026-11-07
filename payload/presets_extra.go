package payload

// Extra presets from the HTTP-Injector style payload set. They are registered
// next to the built-in ones in payload.go and never replace a built-in name,
// so @get, @head and @post keep their meaning.
//
//	@ssh-ws                    GET / with Upgrade: websocket, plain text (SSHWebSocket)
//	@ssh-ws/tcp, @ssh-ws/udp   CONNECT host:port with an Upgrade: websocket header
//	                           (the SSH-over-WebSocket variant that goes through a
//	                           CONNECT-capable front; both names are the same payload)
//	@get-proxy                 GET http://host/ (absolute URI, as sent to an HTTP proxy)
//	@head-proxy                HEAD http://host/
//	@post-proxy                POST http://host/ with an empty body
var extraPresets = map[string]string{
	"@ssh-ws":     SSHWebSocket,
	"@get-proxy":  "GET http://[host]/ [protocol][crlf]Host: [host][crlf]User-Agent: [ua][crlf]Connection: Keep-Alive[crlf][crlf]",
	"@head-proxy": "HEAD http://[host]/ [protocol][crlf]Host: [host][crlf]User-Agent: [ua][crlf]Connection: Keep-Alive[crlf][crlf]",
	"@post-proxy": "POST http://[host]/ [protocol][crlf]Host: [host][crlf]User-Agent: [ua][crlf]Content-Length: 0[crlf]Connection: Keep-Alive[crlf][crlf]",
	"@ssh-ws/tcp": "CONNECT [host_port] [protocol][crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Sec-WebSocket-Version: 13[crlf][crlf]",
	"@ssh-ws/udp": "CONNECT [host_port] [protocol][crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Sec-WebSocket-Version: 13[crlf][crlf]",
}

func init() {
	for name, tpl := range extraPresets {
		if _, taken := presets[name]; !taken {
			presets[name] = tpl
		}
	}
}
