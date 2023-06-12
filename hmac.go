package captain

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

type Opt func(HMAC) HMAC

func WithSHA256(secrets ...string) Opt {
	return func(h HMAC) HMAC {
		h.Hashes = MergeHashes(h.Hashes, NewSHA256(secrets...))
		return h
	}
}

func WithSHA512(secrets ...string) Opt {
	return func(h HMAC) HMAC {
		h.Hashes = MergeHashes(h.Hashes, NewSHA512(secrets...))
		return h
	}
}

func WithNoPrefix() Opt {
	return func(h HMAC) HMAC {
		h.NoPrefix = true
		return h
	}
}

func New(opts ...Opt) HMAC {
	h := HMAC{
		Hashes:   map[Algorithm][]hash.Hash{},
		NoPrefix: false,
	}
	for _, opt := range opts {
		h = opt(h)
	}

	return h
}

func (h HMAC) Sign(data []byte) (map[Algorithm][]string, error) {
	sigs := map[Algorithm][]string{}
	for algo, hshs := range h.Hashes {
		for _, hsh := range hshs {
			_, err := hsh.Write(data)
			if err != nil {
				return nil, err
			}
			sig := hex.EncodeToString(hsh.Sum(nil))
			if !h.NoPrefix {
				sig = fmt.Sprintf("%s=%s", algo, sig)
			}
			sigs[algo] = append(sigs[algo], sig)
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
