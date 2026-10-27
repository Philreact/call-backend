package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// stderr is collected by Docker. stdout is reserved for the startup protocol.
// Never log attach metadata, tokens, application payloads or raw peer errors.
type transportDiagnostics struct {
	mu                sync.Mutex
	logger            *slog.Logger
	window            time.Time
	count, suppressed int
}

func newTransportDiagnostics(w io.Writer) *transportDiagnostics {
	return &transportDiagnostics{logger: slog.New(slog.NewJSONHandler(w, nil))}
}

var diagnostics = newTransportDiagnostics(os.Stderr)

func (d *transportDiagnostics) record(event, connection, stage, code string, started time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if now.Sub(d.window) >= time.Minute {
		d.window, d.count = now, 0
	}
	// Bound unauthenticated log volume without changing connection admission.
	if d.count >= 120 {
		d.suppressed++
		return
	}
	d.count++
	d.logger.Info("private transport setup", "event", event, "connection_id", connection,
		"stage", stage, "error_code", code, "elapsed_ms", now.Sub(started).Milliseconds(),
		"suppressed_since_last_log", d.suppressed)
	d.suppressed = 0
}

func setupErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var handshake *quic.HandshakeTimeoutError
	var idle *quic.IdleTimeoutError
	var transport *quic.TransportError
	var application *quic.ApplicationError
	var stream *quic.StreamError
	var network net.Error
	switch {
	case errors.As(err, &handshake):
		return "QUIC_HANDSHAKE_TIMEOUT"
	case errors.As(err, &idle):
		return "QUIC_IDLE_TIMEOUT"
	case errors.As(err, &transport):
		return fmt.Sprintf("QUIC_TRANSPORT_%x_REMOTE_%t", uint64(transport.ErrorCode), transport.Remote)
	case errors.As(err, &application):
		return fmt.Sprintf("QUIC_APPLICATION_%x_REMOTE_%t", uint64(application.ErrorCode), application.Remote)
	case errors.As(err, &stream):
		return fmt.Sprintf("QUIC_STREAM_%x_REMOTE_%t", uint64(stream.ErrorCode), stream.Remote)
	case errors.Is(err, context.DeadlineExceeded):
		return "DEADLINE_EXCEEDED"
	case errors.Is(err, context.Canceled):
		return "CANCELLED"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "UNEXPECTED_EOF"
	case errors.As(err, &network) && network.Timeout():
		return "IO_TIMEOUT"
	}
	// Only known internal errors may cross the logging boundary.
	switch err.Error() {
	case "AUTHENTICATION_REQUIRED", "ATTACH_TOKEN_REJECTED", "BACKEND_ACCESS_DENIED", "BUSY", "STORAGE_UNAVAILABLE":
		return err.Error()
	case "control unavailable":
		return "CONTROL_UNAVAILABLE"
	case "invalid frame":
		return "INVALID_FRAME"
	default:
		return "INTERNAL_ERROR"
	}
}
