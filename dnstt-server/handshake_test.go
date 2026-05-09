package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestEncodeHandshakeParams_NoToken(t *testing.T) {
	got := encodeHandshakeParams(handshakeParams{FECData: 4, FECParity: 2, Compress: true}, nil)
	want := []byte{4, 2, 0x01, 0}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestEncodeHandshakeParams_WithToken(t *testing.T) {
	var token [32]byte
	for i := range token {
		token[i] = byte(0xA0 + i)
	}
	got := encodeHandshakeParams(handshakeParams{FECData: 4, FECParity: 2, Compress: true}, token[:])

	want := make([]byte, 0, handshakeParamsLen+32)
	want = append(want, 4, 2, 0x03, 0)
	want = append(want, token[:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestDecodeHandshakeParams(t *testing.T) {
	var goodToken [32]byte
	for i := range goodToken {
		goodToken[i] = byte(0xA0 + i)
	}
	withTokenInput := append([]byte{4, 2, 0x03, 0}, goodToken[:]...)

	for _, tc := range []struct {
		name        string
		input       []byte
		wantParams  handshakeParams
		wantToken   []byte
		wantErrFrag string
	}{
		{"happy no token", []byte{4, 2, 0x01, 0}, handshakeParams{FECData: 4, FECParity: 2, Compress: true}, nil, ""},
		{"zero", []byte{0, 0, 0, 0}, handshakeParams{}, nil, ""},
		{"happy with token", withTokenInput, handshakeParams{FECData: 4, FECParity: 2, Compress: true}, goodToken[:], ""},
		{"too short", []byte{1, 2, 3}, handshakeParams{}, nil, "expected 4 bytes"},
		{"too long no token", []byte{1, 2, 0x01, 0, 99}, handshakeParams{}, nil, "expected 4 bytes"},
		{"empty", []byte{}, handshakeParams{}, nil, "expected 4 bytes"},
		{"reserved flag bits", []byte{0, 0, 0x04, 0}, handshakeParams{}, nil, "reserved bits"},
		{"reserved flag bits high", []byte{0, 0, 0xFC, 0}, handshakeParams{}, nil, "reserved bits"},
		{"reserved byte set", []byte{0, 0, 0, 0xAA}, handshakeParams{}, nil, "reserved byte"},
		{"token bit set but missing token bytes", []byte{0, 0, 0x02, 0}, handshakeParams{}, nil, "auth token bit set but"},
		{"token bit set with wrong size", append([]byte{0, 0, 0x02, 0}, make([]byte, 31)...), handshakeParams{}, nil, "auth token bit set but"},
		{"trailing bytes without token bit", append([]byte{0, 0, 0, 0}, make([]byte, 32)...), handshakeParams{}, nil, "expected 4 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotParams, gotToken, err := decodeHandshakeParams(tc.input)
			if tc.wantErrFrag != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got params=%+v token=%x", tc.wantErrFrag, gotParams, gotToken)
				}
				if !strings.Contains(err.Error(), tc.wantErrFrag) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErrFrag, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotParams != tc.wantParams {
				t.Fatalf("params: got %+v, want %+v", gotParams, tc.wantParams)
			}
			if !bytes.Equal(gotToken, tc.wantToken) {
				t.Fatalf("token: got %x, want %x", gotToken, tc.wantToken)
			}
		})
	}
}

func TestValidateHandshakeParams(t *testing.T) {
	server := handshakeParams{FECData: 4, FECParity: 2, Compress: true}
	if err := validateHandshakeParams(server, server); err != nil {
		t.Fatalf("matching params should pass, got %v", err)
	}
	client := handshakeParams{FECData: 0, FECParity: 0, Compress: true}
	if err := validateHandshakeParams(client, server); err == nil {
		t.Fatal("mismatched FEC should fail")
	}
}

func TestNewHandshakeParamsFromInts(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fecData     int
		fecParity   int
		compress    bool
		want        handshakeParams
		wantErrFrag string
	}{
		{"happy", 4, 2, true, handshakeParams{FECData: 4, FECParity: 2, Compress: true}, ""},
		{"zero", 0, 0, false, handshakeParams{}, ""},
		{"max", 255, 255, false, handshakeParams{FECData: 255, FECParity: 255}, ""},
		{"fec-data negative", -1, 0, false, handshakeParams{}, "fec-data must be in [0,255]"},
		{"fec-data too big", 256, 0, false, handshakeParams{}, "fec-data must be in [0,255]"},
		{"fec-parity negative", 0, -1, false, handshakeParams{}, "fec-parity must be in [0,255]"},
		{"fec-parity too big", 0, 256, false, handshakeParams{}, "fec-parity must be in [0,255]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newHandshakeParamsFromInts(tc.fecData, tc.fecParity, tc.compress)
			if tc.wantErrFrag != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got %+v", tc.wantErrFrag, got)
				}
				if !strings.Contains(err.Error(), tc.wantErrFrag) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErrFrag, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestHandshakeParams_RoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params handshakeParams
		token  []byte
	}{
		{"no token", handshakeParams{FECData: 4, FECParity: 2, Compress: true}, nil},
		{"empty slice (treated as no token)", handshakeParams{FECData: 4, FECParity: 2, Compress: true}, []byte{}},
		{"with token", handshakeParams{FECData: 0, FECParity: 0, Compress: false}, func() []byte {
			b := make([]byte, authTokenLen)
			for i := range b {
				b[i] = byte(0xCD ^ i)
			}
			return b
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := encodeHandshakeParams(tc.params, tc.token)
			gotParams, gotToken, err := decodeHandshakeParams(wire)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if gotParams != tc.params {
				t.Fatalf("params: got %+v, want %+v", gotParams, tc.params)
			}
			// Empty slice should round-trip as no-token (decoder returns nil).
			if len(tc.token) == 0 {
				if gotToken != nil {
					t.Fatalf("expected nil token for no-token round trip, got %x", gotToken)
				}
				return
			}
			if !bytes.Equal(gotToken, tc.token) {
				t.Fatalf("token: got %x, want %x", gotToken, tc.token)
			}
		})
	}
}

func TestEncodeHandshakeParams_WrongTokenSizePanics(t *testing.T) {
	for _, badLen := range []int{1, 16, 31, 33, 64} {
		t.Run(fmt.Sprintf("len_%d", badLen), func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("expected panic for token len=%d, got none", badLen)
				}
			}()
			encodeHandshakeParams(handshakeParams{}, make([]byte, badLen))
		})
	}
}
