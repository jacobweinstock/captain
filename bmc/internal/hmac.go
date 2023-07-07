package internal

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
)

// Algorithm is the type for HMAC algorithms.
type Algorithm string

const (
	SHA256      Algorithm = "sha256"
	SHA256Short Algorithm = "256"
	SHA512      Algorithm = "sha512"
	SHA512Short Algorithm = "512"
)

// HMAC is the HMAC configuration for signing data.
type HMAC struct {
	// Hashes is a map of algorithms to a slice of hash.Hash. The slice is used to support multiple secrets.
	Hashes map[Algorithm][]hash.Hash
	// NoPrefix doesn't prefix the algorithm to the signature. The default is for the prefix to be added. Example: sha256=abc123
	NoPrefix bool
}

func NewHMAC() HMAC {
	h := HMAC{
		Hashes:   map[Algorithm][]hash.Hash{},
		NoPrefix: false,
	}

	return h
}

func (h HMAC) Sign(data []byte) (map[Algorithm][]string, error) {
	sigs := map[Algorithm][]string{}
	for algo, hshs := range h.Hashes {
		for _, hsh := range hshs {
			if _, err := hsh.Write(data); err != nil {
				return nil, err
			}
			sig := hex.EncodeToString(hsh.Sum(nil))
			if !h.NoPrefix {
				sig = fmt.Sprintf("%s=%s", algo, sig)
			}
			sigs[algo] = append(sigs[algo], sig)
			// reset so Sign can be called multiple times. Otherwise, the next call will append to the previous one.
			hsh.Reset()
		}
	}

	return sigs, nil
}

// Equal compares two HMACs.
// Equal means that the data is signed by at least one of the secrets of both HMACs.
func Equal(one, two []string) bool {
	for _, o := range one {
		for _, t := range two {
			if hmac.Equal([]byte(o), []byte(t)) {
				return true
			}
		}
	}

	return false
}

func NewSHA256(secret ...string) map[Algorithm][]hash.Hash {
	var hsh []hash.Hash
	for _, s := range secret {
		hsh = append(hsh, hmac.New(sha256.New, []byte(s)))
	}
	return map[Algorithm][]hash.Hash{SHA256: hsh}
}

func NewSHA512(secret ...string) map[Algorithm][]hash.Hash {
	var hsh []hash.Hash
	for _, s := range secret {
		hsh = append(hsh, hmac.New(sha512.New, []byte(s)))
	}
	return map[Algorithm][]hash.Hash{SHA512: hsh}
}

func MergeHashes(hashes ...map[Algorithm][]hash.Hash) map[Algorithm][]hash.Hash {
	m := map[Algorithm][]hash.Hash{}
	for _, h := range hashes {
		for k, v := range h {
			m[k] = append(m[k], v...)
		}
	}
	return m
}
