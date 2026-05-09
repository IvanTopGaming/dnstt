package main

import (
	"errors"
	"fmt"
)

// handshakeParamsLen is the wire size of the fixed-length prefix of a
// serialized handshake payload. The full payload is either
// handshakeParamsLen bytes (no auth token) or handshakeParamsLen + 32
// bytes (auth token present).
const handshakeParamsLen = 4

// authTokenLen is the wire size of an auth token.
const authTokenLen = 32

// flag bit positions inside byte 2 of the wire format.
const (
	flagCompress     = 0x01
	flagHasAuthToken = 0x02
	// flagsKnownMask covers every defined flag bit. Bits outside this
	// mask must be zero on the wire — decode rejects unknown bits so
	// future-version clients fail closed against current-version servers.
	flagsKnownMask = flagCompress | flagHasAuthToken
)

// handshakeParams are the per-session parameters the client sends inside the
// first Noise handshake message so the server can verify they match its own
// configuration. A mismatch makes the tunnel silently malfunction, so this
// negotiation lets us fail closed at handshake time with a clear message.
type handshakeParams struct {
	FECData   uint8
	FECParity uint8
	Compress  bool
}

// encodeHandshakeParams serializes p plus an optional 32-byte auth token to
// the wire format. Layout:
//
//	[0]   uint8  fec_data
//	[1]   uint8  fec_parity
//	[2]   uint8  flags (bit 0: compress, bit 1: has_auth_token)
//	[3]   uint8  reserved (=0)
//	[4..] [32]   auth_token (only present if has_auth_token bit is set)
//
// authToken may be nil (no token) or exactly authTokenLen bytes.
func encodeHandshakeParams(p handshakeParams, authToken []byte) []byte {
	if len(authToken) > 0 && len(authToken) != authTokenLen {
		panic(fmt.Sprintf("encodeHandshakeParams: auth token must be %d bytes, got %d", authTokenLen, len(authToken)))
	}
	size := handshakeParamsLen
	if len(authToken) > 0 {
		size += authTokenLen
	}
	buf := make([]byte, 0, size)

	flags := byte(0)
	if p.Compress {
		flags |= flagCompress
	}
	if len(authToken) > 0 {
		flags |= flagHasAuthToken
	}
	buf = append(buf, p.FECData, p.FECParity, flags, 0 /* reserved */)
	if len(authToken) > 0 {
		buf = append(buf, authToken...)
	}
	return buf
}

// decodeHandshakeParams parses the wire format. Returns the params plus the
// optional auth token (nil if has_auth_token bit was clear). Returns an
// error if the input length, reserved bits, or auth-token-bit/length pairing
// is invalid.
func decodeHandshakeParams(b []byte) (handshakeParams, []byte, error) {
	if len(b) < handshakeParamsLen {
		return handshakeParams{}, nil, fmt.Errorf("handshake params: expected %d bytes, got %d",
			handshakeParamsLen, len(b))
	}
	flags := b[2]
	if flags&^flagsKnownMask != 0 {
		return handshakeParams{}, nil, fmt.Errorf("handshake params: reserved bits set in flags byte (got %#02x)", flags)
	}
	if b[3] != 0 {
		return handshakeParams{}, nil, fmt.Errorf("handshake params: reserved byte must be 0 (got %#02x)", b[3])
	}

	hasToken := flags&flagHasAuthToken != 0
	var expectedLen int
	if hasToken {
		expectedLen = handshakeParamsLen + authTokenLen
	} else {
		expectedLen = handshakeParamsLen
	}
	if len(b) != expectedLen {
		if hasToken {
			return handshakeParams{}, nil, fmt.Errorf("handshake params: auth token bit set but payload is %d bytes (expected %d)", len(b), expectedLen)
		}
		return handshakeParams{}, nil, fmt.Errorf("handshake params: expected %d bytes, got %d", expectedLen, len(b))
	}

	params := handshakeParams{
		FECData:   b[0],
		FECParity: b[1],
		Compress:  flags&flagCompress != 0,
	}
	var token []byte
	if hasToken {
		token = make([]byte, authTokenLen)
		copy(token, b[handshakeParamsLen:])
	}
	return params, token, nil
}

// validateHandshakeParams returns nil if client and server params match, or
// an error describing the mismatch otherwise.
func validateHandshakeParams(client, server handshakeParams) error {
	if client == server {
		return nil
	}
	return errors.New(formatParamMismatch(client, server))
}

func formatParamMismatch(client, server handshakeParams) string {
	return fmt.Sprintf(
		"client param mismatch: client fec-data=%d fec-parity=%d compress=%v; server fec-data=%d fec-parity=%d compress=%v",
		client.FECData, client.FECParity, client.Compress,
		server.FECData, server.FECParity, server.Compress,
	)
}

// newHandshakeParamsFromInts builds a handshakeParams from CLI-provided
// ints, enforcing the [0, 255] uint8 range so silent truncation cannot
// happen. Returns an error suitable for printing directly to the user.
func newHandshakeParamsFromInts(fecData, fecParity int, compress bool) (handshakeParams, error) {
	if fecData < 0 || fecData > 255 {
		return handshakeParams{}, fmt.Errorf("fec-data must be in [0,255], got %d", fecData)
	}
	if fecParity < 0 || fecParity > 255 {
		return handshakeParams{}, fmt.Errorf("fec-parity must be in [0,255], got %d", fecParity)
	}
	return handshakeParams{
		FECData:   uint8(fecData),
		FECParity: uint8(fecParity),
		Compress:  compress,
	}, nil
}
