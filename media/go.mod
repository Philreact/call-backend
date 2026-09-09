module qortal.org/qapp-backend-call/media

go 1.26.0

replace github.com/mengelbart/moqtransport => ./third_party/moqtransport

require (
	github.com/mengelbart/moqtransport v0.0.0
	github.com/quic-go/quic-go v0.62.0
)

require (
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
