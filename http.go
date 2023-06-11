package captain

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Signature struct {
	// Header is the header name that should contain the signature(s). Example: X-Rufio-Signature
	Header string
	// DontAppendAlgoToHeader appends the algorithm to the signature header. Example: X-Rufio-Signature becomes X-Rufio-Signature-256
	DontAppendAlgoToHeader bool
	// PayloadHeaders are headers whose values will be included in the signature payload. Example: X-Rufio-Timestamp
	PayloadHeaders []string
	// HMAC is the HMAC to use for signing
	HMAC HMAC
}

func (s Signature) AddSignature(req *http.Request) error {
	// do signing
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	// add headers to signature payload
	for _, h := range s.PayloadHeaders {
		if val := req.Header.Get(h); val != "" {
			body = append(body, []byte(val)...)
		}
	}

	signed, err := s.HMAC.Sign(body)
	if err != nil {
		return err
	}

	if s.DontAppendAlgoToHeader {
		all := signed[SHA256]
		all = append(all, signed[SHA512]...)
		req.Header.Add(s.Header, strings.Join(all, ","))
	} else {
		req.Header.Add(fmt.Sprintf("%s-%s", s.Header, SHA256Short), strings.Join(signed[SHA256], ","))
		req.Header.Add(fmt.Sprintf("%s-%s", s.Header, SHA512Short), strings.Join(signed[SHA512], ","))
	}

	return nil
}
