module gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird

require (
	filippo.io/edwards25519 v1.1.0
	github.com/dchest/siphash v1.2.3
	github.com/refraction-networking/utls v1.6.3
	gitlab.com/yawning/edwards25519-extra v0.0.0-20231005122941-2149dcafc266
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.5.0
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel v0.0.0-20240711104640-e64b1b3562f3
	golang.org/x/crypto v0.27.0
	golang.org/x/net v0.29.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/quic-go/quic-go v0.40.1 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/text v0.18.0 // indirect
)

go 1.20
