package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	dialTimeout  = 30 * time.Second
	dialMinDelay = 500 * time.Millisecond
	dialMaxDelay = 30 * time.Second

	// defaultDoTSenders is the default number of concurrent DoT senders,
	// enabling RFC 7858 query pipelining.
	defaultDoTSenders = 8
)

// TLSPacketConn is a TLS- and TCP-based transport for DNS messages, used for
// DNS over TLS (DoT). Its WriteTo and ReadFrom methods exchange DNS messages
// over a TLS channel, prefixing each message with a two-octet length field as
// in DNS over TCP.
//
// TLSPacketConn deals only with already formatted DNS messages. It does not
// handle encoding information into the messages. That is rather the
// responsibility of DNSPacketConn.
//
// https://tools.ietf.org/html/rfc7858
type TLSPacketConn struct {
	// writeMu serialises concurrent writes from multiple sender goroutines
	// so that length+data pairs are never interleaved on the wire.
	writeMu sync.Mutex
	// QueuePacketConn is the direct receiver of ReadFrom and WriteTo calls.
	// recvLoop and sendLoop take the messages out of the receive and send
	// queues and actually put them on the network.
	*turbotunnel.QueuePacketConn
}

// NewTLSPacketConn creates a new TLSPacketConn configured to use the TLS
// server at addr as a DNS over TLS resolver. It maintains a TLS connection to
// the resolver, reconnecting as necessary. numSenders controls how many
// concurrent send goroutines share the connection (RFC 7858 pipelining); pass
// defaultDoTSenders for a sensible default.
func NewTLSPacketConn(addr string, dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error), numSenders int) (*TLSPacketConn, error) {
	if numSenders < 1 {
		numSenders = 1
	}
	dial := func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		defer cancel()
		return dialTLSContext(ctx, "tcp", addr)
	}
	// We maintain one TLS connection at a time, redialing it whenever it
	// becomes disconnected. We do the first dial here, outside the
	// goroutine, so that any immediate and permanent connection errors are
	// reported directly to the caller of NewTLSPacketConn.
	conn, err := dial()
	if err != nil {
		return nil, err
	}
	c := &TLSPacketConn{
		QueuePacketConn: turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, 0),
	}
	go func() {
		defer c.Close()
		backoff := dialMinDelay
		for {
			connStart := time.Now()
			var wg sync.WaitGroup

			// Start one recv goroutine and numSenders send goroutines.
			// When any goroutine terminates (on error or queue close)
			// it closes conn to unblock the others.
			wg.Add(1 + numSenders)
			go func() {
				defer wg.Done()
				if err := c.recvLoop(conn); err != nil {
					log.Printf("DoT recvLoop: %v", err)
				}
				conn.Close() // unblock all senders
			}()
			for i := 0; i < numSenders; i++ {
				go func() {
					defer wg.Done()
					if err := c.sendLoop(conn); err != nil {
						log.Printf("DoT sendLoop: %v", err)
					}
					conn.Close() // unblock recv and other senders
				}()
			}
			wg.Wait()

			// If the connection was stable for longer than dialMaxDelay,
			// reset the backoff so the next reconnect is fast.
			if time.Since(connStart) > dialMaxDelay {
				backoff = dialMinDelay
			}

			// Wait before reconnecting to avoid a tight reconnect loop.
			// Add ±25% jitter to spread out reconnect storms.
			jitter := time.Duration(rand.Int63n(int64(backoff)/2+1)) - backoff/4
			delay := backoff + jitter
			log.Printf("DoT: reconnecting in %v", delay)
			select {
			case <-time.After(delay):
			case <-c.QueuePacketConn.Closed():
				return
			}

			metricTLSReconnects.Add(1)
			// Use a temporary variable so conn is never set to nil on failure.
			// If dial fails, keep the old (dead) connection; goroutines started
			// on it exit immediately, and the loop retries after the next
			// backoff interval instead of giving up permanently.
			newConn, dialErr := dial()
			backoff *= 2
			if backoff > dialMaxDelay {
				backoff = dialMaxDelay
			}
			if dialErr != nil {
				log.Printf("DoT: reconnect failed: %v; retrying", dialErr)
				continue
			}
			conn = newConn
		}
	}()
	return c, nil
}

// recvLoop reads length-prefixed messages from conn and passes them to the
// incoming queue.
func (c *TLSPacketConn) recvLoop(conn net.Conn) error {
	br := bufio.NewReader(conn)
	for {
		var length uint16
		err := binary.Read(br, binary.BigEndian, &length)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return err
		}
		p := make([]byte, int(length))
		_, err = io.ReadFull(br, p)
		if err != nil {
			return err
		}
		c.QueuePacketConn.QueueIncoming(p, turbotunnel.DummyAddr{})
	}
}

// sendLoop reads messages from the outgoing queue and writes them,
// length-prefixed, to conn. Multiple sendLoop goroutines may run concurrently
// on the same conn; writeMu ensures their writes do not interleave.
func (c *TLSPacketConn) sendLoop(conn net.Conn) error {
	for p := range c.QueuePacketConn.OutgoingQueue(turbotunnel.DummyAddr{}) {
		if err := c.writeMsg(conn, p); err != nil {
			return err
		}
	}
	return nil
}

// writeMsg writes a single length-prefixed DNS message to conn under writeMu.
func (c *TLSPacketConn) writeMsg(conn net.Conn, p []byte) error {
	length := uint16(len(p))
	if int(length) != len(p) {
		log.Printf("DoT: dropping packet of %d bytes (too long to encode)", len(p))
		return nil
	}
	// Build a single buffer so the length and data are written atomically
	// without requiring a buffered writer per goroutine.
	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf, length)
	copy(buf[2:], p)
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := conn.Write(buf)
	return err
}
