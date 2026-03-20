package main

import (
	"fmt"
	"log"
	"net"
)

// transportMaker is a function that creates a transport PacketConn along with
// the remote address to use for WriteTo calls. The returned PacketConn is
// already wrapped in a DNSPacketConn if appropriate.
type transportMaker func() (net.PacketConn, net.Addr, error)

// tryTransports attempts each non-nil maker in order and returns the first
// successful result. It is used for automatic transport selection (DoQ → DoT →
// DoH → UDP).
func tryTransports(makers []struct {
	name string
	make transportMaker
}) (net.PacketConn, net.Addr, error) {
	var lastErr error
	for _, m := range makers {
		pconn, addr, err := m.make()
		if err == nil {
			log.Printf("auto: using %s transport", m.name)
			return pconn, addr, nil
		}
		log.Printf("auto: %s unavailable: %v", m.name, err)
		lastErr = err
	}
	if lastErr != nil {
		return nil, nil, fmt.Errorf("auto: all transports failed; last error: %w", lastErr)
	}
	return nil, nil, fmt.Errorf("auto: no transports configured")
}
