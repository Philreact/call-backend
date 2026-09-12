package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"golang.org/x/sys/unix"
)

const chunkSize = 32768

var fileIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type chunk struct {
	Index  int    `json:"index"`
	Length int    `json:"length"`
	Digest string `json:"digest"`
	data   []byte
}
type fileRequest struct {
	Type    string  `json:"type"`
	Op      string  `json:"op"`
	ID      string  `json:"id"`
	Index   int     `json:"index"`
	Chunk   string  `json:"chunk"`
	Chunks  []chunk `json:"chunks,omitempty"`
	Indices []int   `json:"indices,omitempty"`
	Lease   string  `json:"lease,omitempty"`
}

func parseBatch(data []byte) (fileRequest, error) {
	r := fileRequest{Op: "prepare"}
	if len(data) < 22 || string(data[:4]) != "QFB1" {
		return r, errors.New("INVALID_REQUEST")
	}
	r.ID = hex.EncodeToString(data[4:20])
	count := int(binary.BigEndian.Uint16(data[20:22]))
	data = data[22:]
	if count < 1 || count > 16 {
		return r, errors.New("INVALID_REQUEST")
	}
	seen := map[int]bool{}
	for range count {
		if len(data) < 8 {
			return r, errors.New("INVALID_REQUEST")
		}
		index, length := int(binary.BigEndian.Uint32(data[:4])), int(binary.BigEndian.Uint32(data[4:8]))
		data = data[8:]
		if length < 28 || length > chunkSize+28 || length > len(data) || seen[index] {
			return r, errors.New("INVALID_CHUNK")
		}
		seen[index] = true
		hash := sha256.Sum256(data[:length])
		r.Chunks = append(r.Chunks, chunk{Index: index, Length: length, Digest: hex.EncodeToString(hash[:]), data: data[:length]})
		data = data[length:]
	}
	if len(data) != 0 {
		return r, errors.New("INVALID_REQUEST")
	}
	return r, nil
}
func lockFile(ctx context.Context, directory, id string, exclusive bool) (*os.File, error) {
	if !fileIDPattern.MatchString(id) {
		return nil, errors.New("NOT_AVAILABLE")
	}
	fd, err := unix.Open(filepath.Join(directory, "locks", id[:2]), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "file-lock")
	mode := unix.LOCK_SH
	if exclusive {
		mode = unix.LOCK_EX
	}
	for {
		err = unix.Flock(fd, mode|unix.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}
func openBlob(directory, id string, write bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if write {
		flags = unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	}
	fd, err := unix.Open(filepath.Join(directory, id+".bin"), flags, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "encrypted-blob"), nil
}
func fileOperation(ctx context.Context, c *control, connection, directory string, r fileRequest) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	lock, err := lockFile(ctx, directory, r.ID, r.Op != "get")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	// The shared lock stays held through authorization, disk sync and metadata
	// commit. A timeout/crash cannot expose uncommitted chunks or race cleanup.
	query := func(request fileRequest) (json.RawMessage, error) {
		return c.call(ctx, controlMessage{Op: "file", Connection: connection, Metadata: request})
	}
	if r.Op == "get" {
		r.Op = "read"
		result, err := query(r)
		if err != nil {
			return nil, err
		}
		var plan struct {
			Length int `json:"length"`
		}
		if json.Unmarshal(result, &plan) != nil || plan.Length < 28 || plan.Length > chunkSize+28 {
			return nil, errors.New("FILE_DAMAGED")
		}
		f, err := openBlob(directory, r.ID, false)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		data := make([]byte, plan.Length)
		if _, err = f.ReadAt(data, int64(r.Index)*(chunkSize+28)); err != nil {
			return nil, errors.New("FILE_DAMAGED")
		}
		// A revoked connection is closed by control; don't emit an already read chunk.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return json.Marshal(map[string]any{"chunk": base64.StdEncoding.EncodeToString(data)})
	}
	r.Op = "prepare"
	result, err := query(r)
	if err != nil {
		return nil, err
	}
	var plan struct {
		Write []int  `json:"write"`
		Lease string `json:"lease"`
	}
	if json.Unmarshal(result, &plan) != nil {
		return nil, errors.New("INVALID_REQUEST")
	}
	if len(plan.Lease) != 32 {
		return nil, errors.New("INVALID_REQUEST")
	}
	if len(plan.Write) > 0 {
		f, err := openBlob(directory, r.ID, true)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		writes := map[int]bool{}
		for _, i := range plan.Write {
			writes[i] = true
		}
		for _, chunk := range r.Chunks {
			if !writes[chunk.Index] {
				continue
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			n, err := f.WriteAt(chunk.data, int64(chunk.Index)*(chunkSize+28))
			if err != nil {
				return nil, err
			}
			if n != len(chunk.data) {
				return nil, io.ErrShortWrite
			}
		}
		if err = f.Sync(); err != nil {
			return nil, err
		}
	}
	r.Op = "commit"
	r.Lease = plan.Lease
	return query(r)
}

// fileDownloadBatch keeps ciphertext out of the Python control plane and
// amortizes request/stream overhead across a bounded 512 KiB response.
func fileDownloadBatch(ctx context.Context, c *control, connection, directory string, r fileRequest) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if len(r.Indices) < 1 || len(r.Indices) > 16 {
		return nil, errors.New("INVALID_REQUEST")
	}
	lock, err := lockFile(ctx, directory, r.ID, false)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	r.Op = "read_batch"
	result, err := c.call(ctx, controlMessage{Op: "file", Connection: connection, Metadata: r})
	if err != nil {
		return nil, err
	}
	var plan struct {
		Indices []int `json:"indices"`
		Lengths []int `json:"lengths"`
	}
	if json.Unmarshal(result, &plan) != nil || len(plan.Indices) != len(r.Indices) || len(plan.Lengths) != len(r.Indices) {
		return nil, errors.New("FILE_DAMAGED")
	}
	total := 6
	for i, index := range plan.Indices {
		if index != r.Indices[i] || plan.Lengths[i] < 28 || plan.Lengths[i] > chunkSize+28 {
			return nil, errors.New("FILE_DAMAGED")
		}
		total += 8 + plan.Lengths[i]
	}
	if total > maxPayload-1 {
		return nil, errors.New("INVALID_REQUEST")
	}
	f, err := openBlob(directory, r.ID, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data := make([]byte, total)
	copy(data, "QFD1")
	binary.BigEndian.PutUint16(data[4:6], uint16(len(plan.Indices)))
	offset := 6
	for i, index := range plan.Indices {
		length := plan.Lengths[i]
		binary.BigEndian.PutUint32(data[offset:offset+4], uint32(index))
		binary.BigEndian.PutUint32(data[offset+4:offset+8], uint32(length))
		offset += 8
		if _, err = f.ReadAt(data[offset:offset+length], int64(index)*(chunkSize+28)); err != nil {
			return nil, errors.New("FILE_DAMAGED")
		}
		offset += length
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return data, nil
}
func publicError(err error) string {
	// Never expose OS paths or internal errors to a peer.
	switch err.Error() {
	case "INVALID_REQUEST", "INVALID_CHUNK", "CHUNK_CONFLICT", "ACCESS_DENIED", "EXPIRED", "UPLOAD_CLOSED", "UPLOAD_INCOMPLETE", "NOT_AVAILABLE", "FILE_DAMAGED", "BUSY", "AUTHENTICATION_REQUIRED", "BACKEND_ACCESS_DENIED":
		return err.Error()
	}
	return "STORAGE_UNAVAILABLE"
}
func applicationResult(result json.RawMessage, err error) []byte {
	if err != nil {
		data, _ := json.Marshal(map[string]any{"ok": false, "error": publicError(err)})
		return append([]byte{0}, data...)
	}
	if result == nil {
		result = json.RawMessage(`{}`)
	}
	return append([]byte{0}, []byte(fmt.Sprintf(`{"ok":true,"result":%s}`, result))...)
}
