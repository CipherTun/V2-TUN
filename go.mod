module io.surprise.vpn

go 1.25

require (
	github.com/quic-go/quic-go v0.65.0
	github.com/refraction-networking/utls v1.8.2
)

// golang.org/x/crypto, golang.org/x/net and gvisor.dev/gvisor are resolved to
// their latest versions by `go get gvisor.dev/gvisor@go && go get -u ./... && go mod tidy`.
