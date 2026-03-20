package main

// DNS over QUIC (DoQ) transport per RFC 9250.

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const doqDialTimeout = 30 * time.Second

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
	*turbotunnel.QueuePacketConn
}

// NewQUICPacketConn creates a new QUICPacketConn configured to use the DoQ
// server at addr. tlsConfig, if non-nil, is used as the TLS configuration; the
// "doq" ALPN protocol is appended automatically.
func NewQUICPacketConn(addr string, tlsConfig *tls.Config) (*QUICPacketConn, error) {
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
	stream, err := conn.OpenStreamSync(context.Background())
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

// run processes outgoing packets using conn, redialing when the connection
// fails. It exits when the QueuePacketConn is closed.
func (c *QUICPacketConn) run(conn *quic.Conn, dial func() (*quic.Conn, error)) {
	outgoing := c.QueuePacketConn.OutgoingQueue(turbotunnel.DummyAddr{})
	closed := c.QueuePacketConn.Closed()
	for {
		connDone := conn.Context().Done()
		var wg sync.WaitGroup
	connLoop:
		for {
			select {
			case p := <-outgoing:
				wg.Add(1)
				go func(p []byte) {
					defer wg.Done()
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

		var err error
		conn, err = dial()
		if err != nil {
			log.Printf("dial doq: %v", err)
			return
		}
		log.Printf("doq: reconnected to server")
	}
}
