package bmc

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
)

func TestWithLogger(t *testing.T) {
	tests := map[string]struct {
		logger logr.Logger
	}{
		"success": {},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			c := &Config{}
			WithLogger(tc.logger)(c)
			c.Logger.GetSink()
			if c.Logger != tc.logger {
				t.Errorf("expected logger %v, got %v", tc.logger, c.Logger)
			}
			if diff := cmp.Diff(tc.logger, c.Logger); diff != "" {
				t.Errorf("unexpected diff: %s", diff)
			}
		})
	}
}

func TestWithBaseSignatureHeader(t *testing.T) {
	tests := map[string]struct {
		header string
	}{
		"success": {header: "X-Base-Signature"},
		"fail":    {},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			c := New("localhost/webhook", "127.0.0.1", WithBaseSignatureHeader(tc.header))
			if c.BaseSignatureHeader != tc.header {
				t.Errorf("expected header %q, got %q", tc.header, c.BaseSignatureHeader)
			}
		})
	}
}
