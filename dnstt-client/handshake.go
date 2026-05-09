package main

import "fmt"

// handshakeParamsLen is the wire size of the fixed-length prefix of a
// serialized handshake payload.
const handshakeParamsLen = 4

// authTokenLen is the wire size of an auth token.
const authTokenLen = 32

// flag bit positions inside byte 2 of the wire format.
const (
	flagCompress     = 0x01
	flagHasAuthToken = 0x02
)

// handshakeParams mirror the server-side type. The duplication is
// intentional — the two binaries are separate `package main` units.
type handshakeParams struct {
	FECData   uint8
	FECParity uint8
	Compress  bool
}

// encodeHandshakeParams serializes p plus an optional 32-byte auth token
// to the wire format. Layout matches the server-side decoder:
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
