// dnstt-client is the client end of a DNS tunnel.
//
// Usage:
//
//	dnstt-client [-doh URL|-dot ADDR|-udp ADDR] -pubkey-file PUBKEYFILE DOMAIN LOCALADDR
//
// Examples:
//
//	dnstt-client -doh https://resolver.example/dns-query -pubkey-file server.pub t.example.com 127.0.0.1:7000
//	dnstt-client -dot resolver.example:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000
//
// The program supports DNS over HTTPS (DoH), DNS over TLS (DoT), DNS over
// QUIC (DoQ), and UDP DNS. Use one of these options (or -auto to try them in
// order):
//
//	-doh https://resolver.example/dns-query
//	-dot resolver.example:853
//	-doq resolver.example:853
//	-udp resolver.example:53
//	-auto  (tries DoQ→DoT→DoH→UDP in order)
//
// You can give the server's public key as a file or as a hex string. Use
// "dnstt-server -gen-key" to get the public key.
//
//	-pubkey-file server.pub
//	-pubkey 0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
//
// DOMAIN is the root of the DNS zone reserved for the tunnel. See README for
// instructions on setting it up.
//
// LOCALADDR is the TCP address that will listen for connections and forward
// them over the tunnel.
//
// In -doh and -dot modes, the program's TLS fingerprint is camouflaged with
// uTLS by default. The specific TLS fingerprint is selected randomly from a
// weighted distribution. You can set your own distribution (or specific single
// fingerprint) using the -utls option. The special value "none" disables uTLS.
//
//	-utls '3*Firefox,2*Chrome,1*iOS'
//	-utls Firefox
//	-utls none
package main

import (
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	_ "expvar" // register /debug/vars HTTP handler
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof" // register /debug/pprof HTTP handlers
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// smux streams will be closed after this much time without receiving data.
const idleTimeout = 2 * time.Minute

// errRotate is a sentinel returned by sessionLoop to signal that the tunnel
// should reconnect immediately (e.g., for ClientID rotation) without backoff.
var errRotate = errors.New("ClientID rotation")

// fixedAddrConn wraps a net.PacketConn and routes all WriteTo calls to a
// fixed address, regardless of the addr argument. This lets UDP transports
// use turbotunnel.DummyAddr{} as the KCP remote address while still sending
// to the correct DNS resolver.
type fixedAddrConn struct {
	net.PacketConn
	addr net.Addr
}

func (c *fixedAddrConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.PacketConn.WriteTo(p, c.addr)
}

// dnsNameCapacity returns the number of bytes remaining for encoded data after
// including domain in a DNS name.
func dnsNameCapacity(domain dns.Name) int {
	// Names must be 255 octets or shorter in total length.
	// https://tools.ietf.org/html/rfc1035#section-2.3.4
	capacity := 255
	// Subtract the length of the null terminator.
	capacity -= 1
	for _, label := range domain {
		// Subtract the length of the label and the length octet.
		capacity -= len(label) + 1
	}
	// Each label may be up to 63 bytes long and requires 64 bytes to
	// encode.
	capacity = capacity * 63 / 64
	// Base32 expands every 5 bytes to 8.
	capacity = capacity * 5 / 8
	return capacity
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// sampleUTLSDistribution parses a weighted uTLS Client Hello ID distribution
// string of the form "3*Firefox,2*Chrome,1*iOS", matches each label to a
// utls.ClientHelloID from utlsClientHelloIDMap, and randomly samples one
// utls.ClientHelloID from the distribution.
func sampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := parseWeightedList(spec)
	if err != nil {
		return nil, err
	}
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" {
			id = nil
		} else {
			id = utlsLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}

// zlibFlushWriter wraps a zlib.Writer and flushes after every Write to
// prevent buffering-induced hangs in interactive sessions (e.g. SSH).
type zlibFlushWriter struct {
	*zlib.Writer
}

func (w *zlibFlushWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if err == nil && n > 0 {
		err = w.Writer.Flush()
	}
	return n, err
}

func handle(local *net.TCPConn, sess *smux.Session, conv uint32, compress bool) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("session %08x opening stream: %v", conv, err)
	}
	defer func() {
		log.Printf("end stream %08x:%d", conv, stream.ID())
		stream.Close()
	}()
	log.Printf("begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	if compress {
		enc := &zlibFlushWriter{zlib.NewWriter(stream)}
		dec, decErr := zlib.NewReader(stream)
		if decErr != nil {
			return fmt.Errorf("stream %08x:%d zlib reader: %v", conv, stream.ID(), decErr)
		}
		go func() {
			defer wg.Done()
			_, err := io.Copy(enc, local)
			if err == io.EOF {
				err = nil
			}
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("stream %08x:%d copy stream←local (compressed): %v", conv, stream.ID(), err)
			}
			enc.Close()
			local.CloseRead()
			stream.Close()
		}()
		go func() {
			defer wg.Done()
			_, err := io.Copy(local, dec)
			if err == io.EOF {
				err = nil
			}
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("stream %08x:%d copy local←stream (compressed): %v", conv, stream.ID(), err)
			}
			dec.Close()
			local.CloseWrite()
		}()
	} else {
		go func() {
			defer wg.Done()
			_, err := io.Copy(stream, local)
			if err == io.EOF {
				// smux Stream.Write may return io.EOF.
				err = nil
			}
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
			}
			local.CloseRead()
			stream.Close()
		}()
		go func() {
			defer wg.Done()
			_, err := io.Copy(local, stream)
			if err == io.EOF {
				// smux Stream.WriteTo may return io.EOF.
				err = nil
			}
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
			}
			local.CloseWrite()
		}()
	}
	wg.Wait()

	return err
}

// clientKCPConfig holds tunable KCP parameters for the client.
type clientKCPConfig struct {
	nodelay  int
	interval int
	resend   int
	nc       int
	window   int
}

// sessionLoop establishes one KCP+Noise+smux session over pconn, accepts
// connections from ln, and serves them until pconn closes or rotateC fires.
// It returns errRotate if rotateC fired (caller should reconnect immediately),
// or another error / nil otherwise.
func sessionLoop(ctx context.Context, pubkey []byte, domain dns.Name, ln *net.TCPListener, pconn net.PacketConn, rotateC <-chan time.Time, kcpCfg clientKCPConfig, fecData, fecParity int, authToken []byte, compress bool) error {
	defer pconn.Close()

	mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1
	if mtu < 80 {
		return fmt.Errorf("domain %s leaves only %d bytes for payload", domain, mtu)
	}
	log.Printf("effective MTU %d", mtu)

	// Open a KCP conn on the PacketConn.
	remoteAddr := turbotunnel.DummyAddr{}
	conn, err := kcp.NewConn2(remoteAddr, nil, fecData, fecParity, pconn)
	if err != nil {
		return fmt.Errorf("opening KCP conn: %v", err)
	}
	defer func() {
		log.Printf("end session %08x", conn.GetConv())
		conn.Close()
	}()
	log.Printf("begin session %08x", conn.GetConv())
	conn.SetStreamMode(true)
	conn.SetNoDelay(kcpCfg.nodelay, kcpCfg.interval, kcpCfg.resend, kcpCfg.nc)
	conn.SetWindowSize(kcpCfg.window, kcpCfg.window)
	if !conn.SetMtu(mtu) {
		return fmt.Errorf("SetMtu(%d) failed", mtu)
	}

	// Build the Noise handshake payload with the client's advertised
	// parameters and (if -auth-token was given) the auth token. Server
	// validates both inside the handshake — no separate post-Noise
	// auth round-trip.
	clientPayload := encodeHandshakeParams(handshakeParams{
		FECData:   uint8(fecData),
		FECParity: uint8(fecParity),
		Compress:  compress,
	}, authToken)
	rw, err := noise.NewClient(conn, pubkey, clientPayload)
	if err != nil {
		return err
	}

	// Start a smux session on the Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		return fmt.Errorf("opening smux session: %v", err)
	}
	defer sess.Close()

	// acceptCh carries connections from the TCP listener.
	type accepted struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan accepted, 1)
	go func() {
		for {
			c, err := ln.Accept()
			acceptCh <- accepted{c, err}
			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case a := <-acceptCh:
			if a.err != nil {
				return a.err
			}
			go func() {
				defer a.conn.Close()
				err := handle(a.conn.(*net.TCPConn), sess, conn.GetConv(), compress)
				if err != nil {
					log.Printf("handle: %v", err)
				}
			}()
		case <-rotateC:
			log.Printf("rotating ClientID")
			return errRotate
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// run starts the TCP listener and repeatedly calls makeConn + sessionLoop,
// reconnecting on failure. It only returns when ctx is cancelled.
func run(ctx context.Context, pubkey []byte, domain dns.Name, localAddr *net.TCPAddr, makeConn func() (net.PacketConn, error), rotateDuration time.Duration, kcpCfg clientKCPConfig, fecData, fecParity int, authToken []byte, compress bool) error {
	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		pconn, err := makeConn()
		if err != nil {
			log.Printf("transport error: %v", err)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = 2 * time.Second // reset on success

		var rotateC <-chan time.Time
		var rotateTicker *time.Ticker
		if rotateDuration > 0 {
			rotateTicker = time.NewTicker(rotateDuration)
			rotateC = rotateTicker.C
		}

		err = sessionLoop(ctx, pubkey, domain, ln, pconn, rotateC, kcpCfg, fecData, fecParity, authToken, compress)

		if rotateTicker != nil {
			rotateTicker.Stop()
		}

		if err == errRotate {
			// Immediate reconnect for ClientID rotation, no backoff.
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			log.Printf("session ended: %v", err)
		}
		// Brief pause before reconnecting to avoid a tight loop.
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func main() {
	var configFile string
	var dohURL string
	var dohAddr string
	var doqAddr string
	var dotAddr string
	var pubkeyFilename string
	var pubkeyString string
	var udpAddr string
	var utlsDistribution string
	var debugAddr string
	var autoTransport bool
	var pinCerts string
	var pinSkipChain bool
	var rotateID int
	var kcpMode string
	var fecData, fecParity int
	var multipath bool
	var compress bool
	var authToken string
	logLevel := new(slog.LevelVar) // default INFO

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s [-doh URL|-dot ADDR|-doq ADDR|-udp ADDR|-auto] -pubkey-file PUBKEYFILE DOMAIN LOCALADDR

Examples:
  %[1]s -doh https://resolver.example/dns-query -pubkey-file server.pub t.example.com 127.0.0.1:7000
  %[1]s -dot resolver.example:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000
  %[1]s -auto -doq r.example:853 -dot r.example:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000

`, os.Args[0])
		flag.PrintDefaults()
		labels := make([]string, 0, len(utlsClientHelloIDMap))
		labels = append(labels, "none")
		for _, entry := range utlsClientHelloIDMap {
			labels = append(labels, entry.Label)
		}
		fmt.Fprintf(flag.CommandLine.Output(), `
Known TLS fingerprints for -utls are:
`)
		i := 0
		for i < len(labels) {
			var line strings.Builder
			fmt.Fprintf(&line, "  %s", labels[i])
			w := 2 + len(labels[i])
			i++
			for i < len(labels) && w+1+len(labels[i]) <= 72 {
				fmt.Fprintf(&line, " %s", labels[i])
				w += 1 + len(labels[i])
				i++
			}
			fmt.Fprintln(flag.CommandLine.Output(), line.String())
		}
	}

	// Register all flags before potentially loading them from a config file.
	flag.StringVar(&configFile, "config", "", "path to configuration file (key=value, # comments)")
	flag.StringVar(&dohURL, "doh", "", "URL of DoH resolver")
	flag.StringVar(&dohAddr, "doh-addr", "", "dial this address for DoH instead of resolving the URL host (e.g. 1.2.3.4:443)")
	flag.StringVar(&doqAddr, "doq", "", "address of DoQ resolver (e.g. dns.example.com:853)")
	flag.StringVar(&dotAddr, "dot", "", "address of DoT resolver")
	flag.StringVar(&pubkeyString, "pubkey", "", fmt.Sprintf("server public key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "read server public key from file")
	flag.StringVar(&udpAddr, "udp", "", "address of UDP DNS resolver")
	flag.StringVar(&utlsDistribution, "utls",
		"4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13",
		"choose TLS fingerprint from weighted distribution")
	flag.StringVar(&debugAddr, "debug-addr", "", "address for debug HTTP server exposing /debug/vars and /debug/pprof")
	flag.BoolVar(&autoTransport, "auto", false, "auto-select transport: try DoQ→DoT→DoH→UDP in order")
	flag.StringVar(&pinCerts, "pin-cert", "", "comma-separated SHA256:<hex> certificate pins for DoT/DoH/DoQ")
	flag.BoolVar(&pinSkipChain, "pin-cert-skip-chain", false, "with -pin-cert: skip CA chain validation and trust only the pin (use for self-signed pinning)")
	flag.IntVar(&rotateID, "rotate-id", 0, "rotate ClientID every N minutes (0 = disabled)")
	flag.StringVar(&kcpMode, "kcp-mode", "normal", "KCP tuning mode: fast, normal, slow")
	flag.IntVar(&fecData, "fec-data", 0, "FEC data shards (0 = disabled)")
	flag.IntVar(&fecParity, "fec-parity", 0, "FEC parity shards (0 = disabled)")
	flag.BoolVar(&multipath, "multipath", false, "use all configured transports simultaneously (DoH, DoT, UDP only)")
	flag.BoolVar(&compress, "compress", false, "enable zlib compression on streams")
	flag.StringVar(&authToken, "auth-token", "", "64-hex-char auth token sent in the Noise handshake")
	flag.Func("log-level", `minimum log level: debug, info, warn, error (default "info")`, func(s string) error {
		return logLevel.UnmarshalText([]byte(s))
	})

	// Two-phase parse: pre-scan os.Args for -config so we can load it
	// before flag.Parse(), allowing command-line flags to override file values.
	for i, arg := range os.Args[1:] {
		if arg == "-config" || arg == "--config" {
			if i+1 < len(os.Args[1:]) {
				configFile = os.Args[i+2]
			}
		} else if strings.HasPrefix(arg, "-config=") {
			configFile = strings.TrimPrefix(arg, "-config=")
		} else if strings.HasPrefix(arg, "--config=") {
			configFile = strings.TrimPrefix(arg, "--config=")
		}
	}
	if configFile != "" {
		if err := loadConfig(configFile); err != nil {
			fmt.Fprintf(os.Stderr, "config file: %v\n", err)
			os.Exit(1)
		}
	}

	flag.Parse()

	// Validate FEC params at startup so out-of-range values fail fast,
	// before any KCP setup or reconnect loop.
	if _, err := newHandshakeParamsFromInts(fecData, fecParity, compress); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Set up structured logging. slog.SetDefault also redirects log.Printf
	// calls through the slog handler, enabling level filtering for all output.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.TimeValue(a.Value.Time().UTC())
			}
			return a
		},
	})))

	if debugAddr != "" {
		go func() {
			log.Printf("debug HTTP server listening on %s", debugAddr)
			if err := http.ListenAndServe(debugAddr, nil); err != nil {
				log.Printf("debug server: %v", err)
			}
		}()
	}

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}
	domain, err := dns.ParseName(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}
	localAddr, err := net.ResolveTCPAddr("tcp", flag.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var pubkey []byte
	if pubkeyFilename != "" && pubkeyString != "" {
		fmt.Fprintf(os.Stderr, "only one of -pubkey and -pubkey-file may be used\n")
		os.Exit(1)
	} else if pubkeyFilename != "" {
		var err error
		pubkey, err = readKeyFromFile(pubkeyFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read pubkey from file: %v\n", err)
			os.Exit(1)
		}
	} else if pubkeyString != "" {
		var err error
		pubkey, err = noise.DecodeKey(pubkeyString)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pubkey format error: %v\n", err)
			os.Exit(1)
		}
	}
	if len(pubkey) == 0 {
		fmt.Fprintf(os.Stderr, "the -pubkey or -pubkey-file option is required\n")
		os.Exit(1)
	}

	utlsClientHelloID, err := sampleUTLSDistribution(utlsDistribution)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parsing -utls: %v\n", err)
		os.Exit(1)
	}
	if utlsClientHelloID != nil {
		log.Printf("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
	}

	// Parse certificate pins if provided.
	var pins map[[32]byte]struct{}
	if pinCerts != "" {
		pins, err = parsePinSet(pinCerts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parsing -pin-cert: %v\n", err)
			os.Exit(1)
		}
	}

	// Build a base TLS config, applying cert pins if requested.
	baseTLSConfig := &tls.Config{}
	if pins != nil {
		baseTLSConfig = makePinnedTLSConfig(pins, baseTLSConfig, pinSkipChain)
	}

	if dohAddr != "" && dohURL == "" {
		fmt.Fprintf(os.Stderr, "-doh-addr requires -doh\n")
		os.Exit(1)
	}

	// rotateDuration for ClientID rotation.
	var rotateDuration time.Duration
	if rotateID > 0 {
		rotateDuration = time.Duration(rotateID) * time.Minute
		log.Printf("ClientID rotation every %v", rotateDuration)
	}

	// makeDoH builds a DoH transport. Returns a factory closure.
	makeDoH := func() (net.PacketConn, net.Addr, error) {
		addr := turbotunnel.DummyAddr{}
		var rt http.RoundTripper
		if utlsClientHelloID == nil {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = nil
			if dohAddr != "" {
				u, err := url.Parse(dohURL)
				if err != nil {
					return nil, nil, err
				}
				serverName := u.Hostname()
				override := dohAddr
				tlsCfg := baseTLSConfig.Clone()
				tlsCfg.ServerName = serverName
				transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&tls.Dialer{Config: tlsCfg}).DialContext(ctx, network, override)
				}
			} else if pins != nil {
				transport.TLSClientConfig = baseTLSConfig.Clone()
			}
			rt = transport
		} else {
			rt = NewUTLSRoundTripper(nil, utlsClientHelloID, dohAddr)
		}
		pconn, err := NewHTTPPacketConn(rt, dohURL, 32)
		if err != nil {
			return nil, nil, err
		}
		return pconn, addr, nil
	}

	makeDoQ := func() (net.PacketConn, net.Addr, error) {
		addr := turbotunnel.DummyAddr{}
		tlsCfg := baseTLSConfig.Clone()
		pconn, err := NewQUICPacketConn(doqAddr, tlsCfg, defaultDoQWorkers)
		if err != nil {
			return nil, nil, err
		}
		// DoQ has its own length-prefixed framing; no DNSPacketConn wrapping.
		return pconn, addr, nil
	}

	makeDoT := func() (net.PacketConn, net.Addr, error) {
		addr := turbotunnel.DummyAddr{}
		var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
		if utlsClientHelloID == nil {
			dialer := &tls.Dialer{Config: baseTLSConfig}
			dialTLSContext = dialer.DialContext
		} else {
			dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return utlsDialContext(ctx, network, addr, nil, utlsClientHelloID)
			}
		}
		pconn, err := NewTLSPacketConn(dotAddr, dialTLSContext, defaultDoTSenders)
		if err != nil {
			return nil, nil, err
		}
		return pconn, addr, nil
	}

	makeUDP := func() (net.PacketConn, net.Addr, error) {
		remoteAddr, err := net.ResolveUDPAddr("udp", udpAddr)
		if err != nil {
			return nil, nil, err
		}
		udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, nil, err
		}
		// Wrap with fixedAddrConn so DNSPacketConn can use DummyAddr{}
		// as its addr (matching KCP's remote addr) while still routing
		// actual UDP packets to the correct resolver.
		fixed := &fixedAddrConn{udpConn, remoteAddr}
		addr := turbotunnel.DummyAddr{}
		return fixed, addr, nil
	}

	// Parse KCP mode.
	kcpCfg := clientKCPConfig{nodelay: 0, interval: 50, resend: 2, nc: 1, window: 128} // normal default
	switch kcpMode {
	case "fast":
		kcpCfg = clientKCPConfig{nodelay: 1, interval: 20, resend: 2, nc: 1, window: 256}
	case "normal":
		// already set above
	case "slow":
		kcpCfg = clientKCPConfig{nodelay: 0, interval: 100, resend: 0, nc: 0, window: 64}
	default:
		fmt.Fprintf(os.Stderr, "unknown -kcp-mode %q: must be fast, normal, or slow\n", kcpMode)
		os.Exit(1)
	}

	// Parse auth token.
	var authTokenBytes []byte
	if authToken != "" {
		b, err := hex.DecodeString(authToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parsing -auth-token: %v\n", err)
			os.Exit(1)
		}
		if len(b) != 32 {
			fmt.Fprintf(os.Stderr, "-auth-token must be 64 hex chars (32 bytes)\n")
			os.Exit(1)
		}
		authTokenBytes = b
	}

	// Build the makeConn factory that sessionLoop will use.
	// For -auto mode, try transports in order. Otherwise enforce exactly one.
	var makeConn func() (net.PacketConn, error)

	if multipath {
		var conns []net.PacketConn
		if dohURL != "" {
			pconn, _, err := makeDoH()
			if err != nil {
				fmt.Fprintf(os.Stderr, "multipath DoH: %v\n", err)
				os.Exit(1)
			}
			conns = append(conns, pconn)
		}
		if dotAddr != "" {
			pconn, _, err := makeDoT()
			if err != nil {
				fmt.Fprintf(os.Stderr, "multipath DoT: %v\n", err)
				os.Exit(1)
			}
			conns = append(conns, pconn)
		}
		if udpAddr != "" {
			pconn, _, err := makeUDP()
			if err != nil {
				fmt.Fprintf(os.Stderr, "multipath UDP: %v\n", err)
				os.Exit(1)
			}
			conns = append(conns, pconn)
		}
		if len(conns) < 2 {
			fmt.Fprintf(os.Stderr, "-multipath requires at least two of -doh, -dot, -udp\n")
			os.Exit(1)
		}
		// Multipath: bump KCP window to 512 so out-of-order packets arriving
		// via transports with different latencies don't stall the session.
		if kcpCfg.window < 512 {
			kcpCfg.window = 512
		}
		multi := NewMultiPacketConn(conns)
		dnsConn := NewDNSPacketConn(multi, turbotunnel.DummyAddr{}, domain)
		firstConn := dnsConn
		firstUsed := false
		makeConn = func() (net.PacketConn, error) {
			if !firstUsed {
				firstUsed = true
				return firstConn, nil
			}
			// Reconnect: rebuild every transport. Log per-transport failures so
			// silent degradation (e.g., DoH down → 2-of-3 path) is visible.
			var newConns []net.PacketConn
			if dohURL != "" {
				if p, _, e := makeDoH(); e == nil {
					newConns = append(newConns, p)
				} else {
					log.Printf("multipath reconnect: DoH unavailable: %v", e)
				}
			}
			if dotAddr != "" {
				if p, _, e := makeDoT(); e == nil {
					newConns = append(newConns, p)
				} else {
					log.Printf("multipath reconnect: DoT unavailable: %v", e)
				}
			}
			if udpAddr != "" {
				if p, _, e := makeUDP(); e == nil {
					newConns = append(newConns, p)
				} else {
					log.Printf("multipath reconnect: UDP unavailable: %v", e)
				}
			}
			if len(newConns) == 0 {
				return nil, fmt.Errorf("all multipath transports failed")
			}
			return NewDNSPacketConn(NewMultiPacketConn(newConns), turbotunnel.DummyAddr{}, domain), nil
		}
	} else if autoTransport {
		type candidate struct {
			name string
			make transportMaker
			addr string
		}
		candidates := []candidate{
			{"DoQ", makeDoQ, doqAddr},
			{"DoT", makeDoT, dotAddr},
			{"DoH", makeDoH, dohURL},
			{"UDP", makeUDP, udpAddr},
		}
		var makers []struct {
			name string
			make transportMaker
		}
		for _, c := range candidates {
			if c.addr != "" {
				makers = append(makers, struct {
					name string
					make transportMaker
				}{c.name, c.make})
			}
		}
		if len(makers) == 0 {
			fmt.Fprintf(os.Stderr, "-auto requires at least one of -doh, -doq, -dot, -udp\n")
			os.Exit(1)
		}
		makeConn = func() (net.PacketConn, error) {
			bare, _, err := tryTransports(makers)
			if err != nil {
				return nil, err
			}
			// DoQ is already DNS-message-level; everything else needs a DNS wrap.
			if _, isDoQ := bare.(*QUICPacketConn); isDoQ {
				return bare, nil
			}
			return NewDNSPacketConn(bare, turbotunnel.DummyAddr{}, domain), nil
		}
	} else {
		type opt struct {
			s     string
			make  func() (net.PacketConn, net.Addr, error)
			isDoQ bool
		}
		opts := []opt{
			{dohURL, makeDoH, false},
			{doqAddr, makeDoQ, true},
			{dotAddr, makeDoT, false},
			{udpAddr, makeUDP, false},
		}
		var chosen *opt
		for i := range opts {
			if opts[i].s == "" {
				continue
			}
			if chosen != nil {
				fmt.Fprintf(os.Stderr, "only one of -doh, -doq, -dot, and -udp may be given (or use -auto)\n")
				os.Exit(1)
			}
			chosen = &opts[i]
		}
		if chosen == nil {
			fmt.Fprintf(os.Stderr, "one of -doh, -doq, -dot, -udp, or -auto is required\n")
			os.Exit(1)
		}
		bare, _, err := chosen.make()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		var firstConn net.PacketConn
		if chosen.isDoQ {
			firstConn = bare
		} else {
			firstConn = NewDNSPacketConn(bare, turbotunnel.DummyAddr{}, domain)
		}
		firstUsed := false
		makeConn = func() (net.PacketConn, error) {
			if !firstUsed {
				firstUsed = true
				return firstConn, nil
			}
			bare, _, err := chosen.make()
			if err != nil {
				return nil, err
			}
			if chosen.isDoQ {
				return bare, nil
			}
			return NewDNSPacketConn(bare, turbotunnel.DummyAddr{}, domain), nil
		}
	}

	// Set up graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = run(ctx, pubkey, domain, localAddr, makeConn, rotateDuration, kcpCfg, fecData, fecParity, authTokenBytes, compress)
	if err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}
