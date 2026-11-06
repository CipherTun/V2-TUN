module io.surprise.vpn

go 1.27.3

require (
	github.com/quic-go/quic-go v0.65.0
	github.com/refraction-networking/utls v1.8.2
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.60.0
	gvisor.dev/gvisor v0.0.0-20261106024050-6e980c2ddc1e
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)

// golang.org/x/crypto, golang.org/x/net and gvisor.dev/gvisor are resolved to
// their latest versions by `go get gvisor.dev/gvisor@go && go get -u ./... && go mod tidy`.
