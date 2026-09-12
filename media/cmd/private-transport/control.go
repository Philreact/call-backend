package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type controlMessage struct {
	ID         uint64          `json:"id,omitempty"`
	Op         string          `json:"op,omitempty"`
	Connection string          `json:"connection,omitempty"`
	Peer       string          `json:"peer,omitempty"`
	MessageID  string          `json:"messageId,omitempty"`
	Lane       string          `json:"lane,omitempty"`
	Metadata   any             `json:"metadata,omitempty"`
	OK         bool            `json:"ok"`
	Result     json.RawMessage `json:"result,omitempty"`
	Error      string          `json:"error,omitempty"`
	Event      string          `json:"event,omitempty"`
}
type control struct {
	conn     net.Conn
	write    sync.Mutex
	mu       sync.Mutex
	pending  map[uint64]chan controlMessage
	closers  map[string]func()
	sequence atomic.Uint64
	done     chan struct{}
}

func newControl(conn net.Conn) *control {
	c := &control{conn: conn, pending: make(map[uint64]chan controlMessage), closers: make(map[string]func()), done: make(chan struct{})}
	go c.read()
	return c
}
func (c *control) read() {
	defer close(c.done)
	defer c.conn.Close()
	scanner := bufio.NewScanner(c.conn)
	scanner.Buffer(make([]byte, 4096), 128*1024)
	for scanner.Scan() {
		var message controlMessage
		if json.Unmarshal(scanner.Bytes(), &message) != nil {
			return
		}
		c.mu.Lock()
		reply := c.pending[message.ID]
		closer := c.closers[message.Connection]
		c.mu.Unlock()
		if message.Event == "close" && closer != nil {
			closer()
		}
		if reply != nil {
			select {
			case reply <- message:
			default:
			}
		}
	}
}
func (c *control) send(message controlMessage) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if len(data) >= 128*1024 {
		return errors.New("control limit")
	}
	c.write.Lock()
	defer c.write.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = c.conn.Write(append(data, '\n'))
	return err
}
func (c *control) call(ctx context.Context, message controlMessage) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	message.ID = c.sequence.Add(1)
	reply := make(chan controlMessage, 1)
	c.mu.Lock()
	if len(c.pending) >= 512 {
		c.mu.Unlock()
		return nil, errors.New("BUSY")
	}
	c.pending[message.ID] = reply
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, message.ID); c.mu.Unlock() }()
	if err := c.send(message); err != nil {
		return nil, err
	}
	select {
	case value := <-reply:
		if !value.OK {
			return nil, errors.New(value.Error)
		}
		return value.Result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, errors.New("control unavailable")
	}
}
