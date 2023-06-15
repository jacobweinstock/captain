package bmc

import (
	"net/http"

	"github.com/go-logr/logr"
)

func WithLogger(logger logr.Logger) Option {
	return func(c *Config) {
		c.Logger = logger
	}
}

func WithBaseSignatureHeader(header string) Option {
	return func(c *Config) {
		c.BaseSignatureHeader = header
	}
}

func WithSecretsPerAlgo(secrets map[Algorithm][]string) Option {
	return func(c *Config) {
		c.Secrets = secrets
	}
}

func WithTLSCert(cert []byte) Option {
	return func(c *Config) {
		c.TLSCert = cert
	}
}

func WithIncludeAlgoHeader(include bool) Option {
	return func(c *Config) {
		c.IncludeAlgoHeader = include
	}
}

func WithIncludedPayloadHeaders(headers []string) Option {
	return func(c *Config) {
		c.IncludedPayloadHeaders = headers
	}
}

func WithIncludeAlgoPrefix(include bool) Option {
	return func(c *Config) {
		c.IncludeAlgoPrefix = include
	}
}

func WithHTTPClient(client *http.Client) Option {
	return func(c *Config) {
		c.httpClient = client
	}
}

func WithLogNotifications(log bool) Option {
	return func(c *Config) {
		c.LogNotifications = log
	}
}
