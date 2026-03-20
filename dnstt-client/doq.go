package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	doqDialTimeout = 30 * time.Second

	// defaultDoQWorkers is the default number of concurrent QUIC stream
	// workers. Each worker handles one in-flight DoQ query at a time.
	defaultDoQWorkers = 8
)

// QUICPacketConn is a QUIC-based transport for DNS messages, used for DNS over
// QUIC (DoQ). Its WriteTo and ReadFrom methods exchange DNS messages over a
// QUIC connection, opening a new stream per message as required by RFC 9250.
//
// QUICPacketConn deals only with already formatted DNS messages. It does not
// handle encoding information into the messages. That is rather the
// responsibility of DNSPacketConn.
//
// https://www.rfc-editor.org/rfc/rfc9250
type QUICPacketConn struct {
	numWorkers int
	*turbotunnel.QueuePacketConn
}

// NewQUICPacketConn creates a new QUICPacketConn configured to use the DoQ
// server at addr. tlsConfig, if non-nil, is used as the TLS configuration; the
// "doq" ALPN protocol is appended automatically. numWorkers controls the number
// of concurrent QUIC stream workers; pass defaultDoQWorkers for a sensible
// default.
func NewQUICPacketConn(addr string, tlsConfig *tls.Config, numWorkers int) (*QUICPacketConn, error) {
	if numWorkers < 1 {
		numWorkers = 1
	}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, "doq")

	dial := func() (*quic.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), doqDialTimeout)
		defer cancel()
		return quic.DialAddr(ctx, addr, tlsConfig, nil)
	}

	conn, err := dial()
	if err != nil {
		return nil, err
	}

	c := &QUICPacketConn{
		numWorkers:      numWorkers,
		QueuePacketConn: turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, 0),
	}
	go func() {
		defer c.Close()
		c.run(conn, dial)
	}()
	return c, nil
}

// sendQuery sends a DNS query p over a new QUIC stream on conn and queues the
// response for return by a future ReadFrom call.
func (c *QUICPacketConn) sendQuery(conn *quic.Conn, p []byte) error {
	// Use the connection's context so OpenStreamSync unblocks immediately
	// if the QUIC connection dies, rather than blocking forever.
	stream, err := conn.OpenStreamSync(conn.Context())
	if err != nil {
		return fmt.Errorf("opening stream: %v", err)
	}

	if len(p) > 0xffff {
		stream.CancelWrite(0)
		stream.CancelRead(0)
		return fmt.Errorf("dropping packet of %d bytes (too long to encode)", len(p))
	}
	if err := binary.Write(stream, binary.BigEndian, uint16(len(p))); err != nil {
		stream.CancelWrite(0)
		return fmt.Errorf("writing query length: %v", err)
	}
	if _, err := stream.Write(p); err != nil {
		stream.CancelWrite(0)
		return fmt.Errorf("writing query: %v", err)
	}
	// Close the write direction; the server responds on the same stream.
	if err := stream.Close(); err != nil {
		return fmt.Errorf("closing write direction: %v", err)
	}

	var respLen uint16
	if err := binary.Read(stream, binary.BigEndian, &respLen); err != nil {
		stream.CancelRead(0)
		return fmt.Errorf("reading response length: %v", err)
	}
	resp := make([]byte, int(respLen))
	if _, err := io.ReadFull(stream, resp); err != nil {
		stream.CancelRead(0)
		return fmt.Errorf("reading response: %v", err)
	}

	c.QueuePacketConn.QueueIncoming(resp, turbotunnel.DummyAddr{})
	return nil
}

// run processes outgoing packets using conn with a fixed worker pool, redialing
// when the connection fails. It exits when the QueuePacketConn is closed.
func (c *QUICPacketConn) run(conn *quic.Conn, dial func() (*quic.Conn, error)) {
	outgoing := c.QueuePacketConn.OutgoingQueue(turbotunnel.DummyAddr{})
	closed := c.QueuePacketConn.Closed()
	backoff := dialMinDelay
	for {
		connDone := conn.Context().Done()
		// sem limits the number of concurrent in-flight queries.
		sem := make(chan struct{}, c.numWorkers)
		var wg sync.WaitGroup
	connLoop:
		for {
			select {
			case p := <-outgoing:
				sem <- struct{}{} // acquire a worker slot
				wg.Add(1)
				go func(p []byte) {
					defer wg.Done()
					defer func() { <-sem }() // release slot
					if err := c.sendQuery(conn, p); err != nil {
						log.Printf("DoQ: %v", err)
					}
				}(p)
			case <-connDone:
				break connLoop
			case <-closed:
				wg.Wait()
				conn.CloseWithError(0, "closed")
				return
			}
		}
		wg.Wait()
		conn.CloseWithError(0, "reconnecting")

		// Retry loop with exponential backoff instead of giving up on the
		// first failed reconnect attempt.
		metricDoQReconnects.Add(1)
		for {
			jitter := time.Duration(rand.Int63n(int64(backoff)/2+1)) - backoff/4
			delay := backoff + jitter
			log.Printf("DoQ: reconnecting in %v", delay)
			select {
			case <-time.After(delay):
			case <-closed:
				return
			}
			var err error
			conn, err = dial()
			if err == nil {
				log.Printf("DoQ: reconnected")
				backoff = dialMinDelay // reset on success
				break
			}
			log.Printf("DoQ: reconnect failed: %v; retrying", err)
			backoff *= 2
			if backoff > dialMaxDelay {
				backoff = dialMaxDelay
			}
		}
	}
}
