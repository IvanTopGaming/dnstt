package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
)

// authDatabase holds a set of authorized 32-byte tokens.
type authDatabase struct {
	mu     sync.RWMutex
	tokens map[[32]byte]struct{}
}

// newAuthDatabase creates an authDatabase from a slice of tokens.
func newAuthDatabase(tokens [][32]byte) *authDatabase {
	db := &authDatabase{tokens: make(map[[32]byte]struct{}, len(tokens))}
	for _, t := range tokens {
		db.tokens[t] = struct{}{}
	}
	return db
}

// Verify returns true if token is in the authorized set.
func (db *authDatabase) Verify(token [32]byte) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	_, ok := db.tokens[token]
	return ok
}

// Len returns the number of tokens in the database.
func (db *authDatabase) Len() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.tokens)
}

// loadAuthKeysFile reads a file containing one hex-encoded 32-byte token per
// line (comments starting with # are ignored) and returns an authDatabase.
func loadAuthKeysFile(filename string) (*authDatabase, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var tokens [][32]byte
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		// Strip comments.
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		b, err := hex.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", lineNum, err)
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("line %d: token must be 32 bytes (%d bytes given)", lineNum, len(b))
		}
		var token [32]byte
		copy(token[:], b)
		tokens = append(tokens, token)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return newAuthDatabase(tokens), nil
}
