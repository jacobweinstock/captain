package bmc

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Signature contains the configuration for signing HTTP requests.
type Signature struct {
	// BaseHeader is the header name that should contain the signature(s). Example: X-Rufio-Signature
	BaseHeader string
	// DisableAlgoHeader decides whether to append the algorithm to the signature header or not. Default is to append.
	// Example: X-Rufio-Signature becomes X-Rufio-Signature-256
	// When set to false, a header will be added for each algorithm. Example: X-Rufio-Signature-256 and X-Rufio-Signature-512
	DisableAlgoHeader bool
	// PayloadHeaders are headers whose values will be included in the signature payload. Example: X-Rufio-Timestamp
	PayloadHeaders []string
	// HMAC is the HMAC to use for signing
	HMAC HMAC
}

func (s Signature) AddSignature(req *http.Request) error {
	// get the body and reset it.
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	// add headers to signature payload, no space between values.
	for _, h := range s.PayloadHeaders {
		if val := req.Header.Get(h); val != "" {
			body = append(body, []byte(val)...)
		}
	}
	signed, err := s.HMAC.Sign(body)
	if err != nil {
		return err
	}

	if s.DisableAlgoHeader {
		all := signed[SHA256]
		all = append(all, signed[SHA512]...)
		req.Header.Add(s.BaseHeader, strings.Join(all, ","))
	} else {
		if len(signed[SHA256]) > 0 {
			req.Header.Add(fmt.Sprintf("%s-%s", s.BaseHeader, SHA256Short), strings.Join(signed[SHA256], ","))
		}
		if len(signed[SHA512]) > 0 {
			req.Header.Add(fmt.Sprintf("%s-%s", s.BaseHeader, SHA512Short), strings.Join(signed[SHA512], ","))
		}
	}

	return nil
}
