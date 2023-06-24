package bmc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bmc-toolbox/bmclib/v2/providers"
	"github.com/go-logr/logr"
	"github.com/jacobweinstock/captain/bmc/internal"
	"github.com/jacobweinstock/registrar"
)

// Algorithm is the type for HMAC algorithms.
type Algorithm string

// Config defines the configuration for sending webhook notifications.
type Config struct {
	// Host is the BMC ip address or hostname.
	Host string
	// ConsumerURL is the URL where a webhook consumer/listener is running and to which we will send notifications.
	ConsumerURL string
	// Secrets holds the secrets per signing algorithm.
	Secrets map[Algorithm][]string
	// TLSCert is the TLS CA certificate to use. Must be used with UseTLS=true.
	TLSCert []byte
	// BaseSignatureHeader is the header name that should contain the signature(s). Example: X-Rufio-Signature
	BaseSignatureHeader string
	// IncludeAlgoHeader decides whether to append the algorithm to the signature header or not. Default is to append.
	// Example: X-Rufio-Signature becomes X-Rufio-Signature-256
	// When set to false, a header will be added for each algorithm. Example: X-Rufio-Signature-256 and X-Rufio-Signature-512
	IncludeAlgoHeader bool
	// IncludedPayloadHeaders are headers whose values will be included in the signature payload. Example: X-Rufio-Timestamp
	IncludedPayloadHeaders []string
	// IncludeAlgoPrefix will prepend the algorithm and an equal sign to the signature. Example: sha256=abc123
	IncludeAlgoPrefix bool
	// Logger is the logger to use for logging.
	Logger logr.Logger
	// LogNotifications will log the notifications sent to the webhook consumer/listener.
	LogNotifications bool

	// httpClient is the http client used for all methods.
	httpClient *http.Client
	// listenerURL is the URL of the webhook consumer/listener.
	listenerURL *url.URL
	// sig is for adding the signature to the request header.
	sig internal.Signature
	// powerState is the current power state of the BMC. The nature of wehhooks is that the provider (us) does not have
	// an API response contract with the consumer/listener. So we need to keep track of the power state ourselves.
	// This means that only after a successful power state change (PowerSet), we can update this field, with any confidence, with the power state.
	powerState string
}

// Option for setting optional Config values.
type Option func(*Config)

const (
	// ProviderName for the Webook implementation.
	ProviderName = "Webhook"
	// ProviderProtocol for the Webhook implementation.
	ProviderProtocol           = "https"
	SHA256           Algorithm = "sha256"
	SHA256Short      Algorithm = "256"
	SHA512           Algorithm = "sha512"
	SHA512Short      Algorithm = "512"
	timestampHeader            = "X-Rufio-Timestamp"
	signatureHeader            = "X-Rufio-Signature"
)

// Features implemented by the AMT provider.
var Features = registrar.Features{
	providers.FeaturePowerSet,
	providers.FeaturePowerState,
	providers.FeatureBootDeviceSet,
}

// New returns a new Config for this webhook provider.
func New(consumerURL string, host string, opts ...Option) *Config {
	cfg := &Config{
		Host:                   host,
		ConsumerURL:            consumerURL,
		BaseSignatureHeader:    signatureHeader,
		IncludeAlgoHeader:      true,
		IncludedPayloadHeaders: []string{timestampHeader},
		IncludeAlgoPrefix:      true,
		Logger:                 logr.Discard(),
		LogNotifications:       true,
		httpClient:             http.DefaultClient,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// create the http client with the TLS cert if provided.
	if cfg.TLSCert != nil {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(cfg.TLSCert)
		tp := &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caCertPool,
				MinVersion: tls.VersionTLS12,
			},
		}
		cfg.httpClient = &http.Client{Transport: tp}
	}

	// create the signature object
	if len(cfg.Secrets) > 0 {
		// maybe validate BaseSignatureHeader and that there are secrets.
		opts := []internal.Opt{}
		if len(cfg.Secrets[SHA256]) > 0 {
			opts = append(opts, internal.WithSHA256(cfg.Secrets[SHA256]...))
		}
		if len(cfg.Secrets[SHA512]) > 0 {
			opts = append(opts, internal.WithSHA512(cfg.Secrets[SHA512]...))
		}
		cfg.sig = internal.Signature{
			BaseHeader:     cfg.BaseSignatureHeader,
			PayloadHeaders: cfg.IncludedPayloadHeaders,
			HMAC:           internal.NewHMAC(opts...),
		}
	}

	return cfg
}

// Name returns the name of this webhook provider.
func (c *Config) Name() string {
	return ProviderName
}

// Open a connection to the webhook consumer.
// For the webhook provider, Open means validating the Config and
// that communication with the webhook consumer can be established.
func (c *Config) Open(ctx context.Context) error {
	// 1. validate consumerURL is a properly formatted URL.
	// 2. validate that we can communicate with the webhook consumer.

	u, err := url.Parse(c.ConsumerURL)
	if err != nil {
		return err
	}
	c.listenerURL = u
	testReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.listenerURL.String(), nil)
	if err != nil {
		return err
	}
	if _, err := c.httpClient.Do(testReq); err != nil { //nolint:bodyclose // not reading the body
		return err
	}

	return nil
}

// Close a connection to the webhook consumer.
func (c *Config) Close() (err error) {
	return nil
}

// BootDeviceSet sends a next boot device webhook notification.
func (c *Config) BootDeviceSet(ctx context.Context, bootDevice string, setPersistent, efiBoot bool) (ok bool, err error) {
	p := Payload{
		Host: c.Host,
		Task: Task{
			BootDevice: &BootDevice{
				Device:     bootDevice,
				Persistent: setPersistent,
				EFIBoot:    efiBoot,
			},
		},
	}
	req, err := c.createRequest(ctx, p)
	if err != nil {
		return false, err
	}

	return c.signAndSend(p, req)
}

// PowerSet sets the power state of a BMC machine.
func (c *Config) PowerSet(ctx context.Context, state string) (ok bool, err error) {
	switch strings.ToLower(state) {
	case "on", "off", "cycle":
		p := Payload{
			Host: c.Host,
			Task: Task{
				Power: strings.ToLower(state),
			},
		}
		req, err := c.createRequest(ctx, p)
		if err != nil {
			return false, err
		}
		ok, err = c.signAndSend(p, req)
		if err != nil {
			return ok, err
		}
		c.powerState = state
		return ok, nil
	}

	return false, errors.New("requested power state is not supported")
}

// PowerStateGet gets the power state of a BMC machine.
func (c *Config) PowerStateGet(_ context.Context) (state string, err error) {
	if c.powerState != "" {
		return c.powerState, nil
	}

	return "", errors.New("the webhook provider requires PowerSet be called first")
}

func requestKVS(req *http.Request) []interface{} {
	reqBody, err := io.ReadAll(req.Body)
	if err != nil {
		return nil
	}
	req.Body = io.NopCloser(bytes.NewBuffer(reqBody))
	return []interface{}{
		"requestBody", string(reqBody),
		"requestHeaders", req.Header,
	}
}

func responseKVS(resp *http.Response) []interface{} {
	reqBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(reqBody))
	return []interface{}{
		"statusCode", resp.StatusCode,
		"responseBody", string(reqBody),
		"responseHeaders", resp.Header,
	}
}

func (c *Config) createRequest(ctx context.Context, p Payload) (*http.Request, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.listenerURL.String(), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add(timestampHeader, time.Now().Format(time.RFC3339))

	return req, nil
}

func (c *Config) signAndSend(p Payload, req *http.Request) (bool, error) {
	if err := c.sig.AddSignature(req); err != nil {
		return false, err
	}
	// have to copy the body out before sending the request.
	kvs := requestKVS(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		kvs = append(kvs, responseKVS(resp)...)
		kvs = append(kvs, []interface{}{"host", c.Host, "task", p.Task, "consumerURL", c.ConsumerURL})
		if c.LogNotifications {
			c.Logger.Info("sent webhook notification", kvs...)
		}
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	kvs = append(kvs, responseKVS(resp)...)
	kvs = append(kvs, []interface{}{"host", c.Host, "task", p.Task, "consumerURL", c.ConsumerURL}...)
	if c.LogNotifications {
		c.Logger.Info("sent webhook notification", kvs...)
	}
	return true, nil
}
