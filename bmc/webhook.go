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
	"github.com/jacobweinstock/registrar"
)

const (
	// ProviderName for the Webook implementation
	ProviderName = "Webhook"
	// ProviderProtocol for the Webhook implementation
	ProviderProtocol = "https"
)

const (
	timestampHeader = "X-Rufio-Timestamp"
	signatureHeader = "X-Rufio-Signature"
)

var (
	// Features implemented by the AMT provider
	Features = registrar.Features{
		providers.FeaturePowerSet,
		providers.FeaturePowerState,
		providers.FeatureBootDeviceSet,
	}
)

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
	Logger            logr.Logger
	LogNotifications  bool

	httpClient  *http.Client
	consumerURL *url.URL
	sig         Signature
	powerState  string
}

// Option for setting optional Config values
type Option func(*Config)

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
				RootCAs: caCertPool,
			},
		}
		cfg.httpClient = &http.Client{Transport: tp}
	}

	// create the signature object
	if len(cfg.Secrets) > 0 {
		// maybe validate BaseSignatureHeader and that there are secrets.
		opts := []Opt{}
		if len(cfg.Secrets[SHA256]) > 0 {
			opts = append(opts, WithSHA256(cfg.Secrets[SHA256]...))
		}
		if len(cfg.Secrets[SHA512]) > 0 {
			opts = append(opts, WithSHA512(cfg.Secrets[SHA512]...))
		}
		cfg.sig = Signature{
			BaseHeader:     cfg.BaseSignatureHeader,
			PayloadHeaders: cfg.IncludedPayloadHeaders,
			HMAC:           NewHMAC(opts...),
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
	c.consumerURL = u
	testReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.consumerURL.String(), nil)
	if err != nil {
		return err
	}
	if _, err := c.httpClient.Do(testReq); err != nil {
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

	return c.sendNotification(ctx, p, req)
}

// PowerSet sets the power state of a BMC machine
func (c *Config) PowerSet(ctx context.Context, state string) (ok bool, err error) {
	p := Payload{
		Host: c.Host,
		Task: Task{
			Power: strings.ToLower(state),
		},
	}
	switch strings.ToLower(state) {
	case "on", "off", "cycle":
	default:
		return false, errors.New("requested state type unknown or not supported")
	}

	req, err := c.createRequest(ctx, p)
	if err != nil {
		return false, err
	}
	ok, err = c.sendNotification(ctx, p, req)
	if err != nil {
		return ok, err
	}
	c.powerState = state

	return ok, nil
}

// PowerStateGet gets the power state of a BMC machine
func (c *Config) PowerStateGet(ctx context.Context) (state string, err error) {
	if c.powerState != "" {
		return c.powerState, nil
	}

	return "", errors.New("power state unknown")
}

func (c *Config) requestKVS(t Task, req *http.Request) []interface{} {
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

func (c *Config) responseKVS(t Task, resp *http.Response) []interface{} {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.consumerURL.String(), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add(timestampHeader, time.Now().Format(time.RFC3339))

	return req, nil
}

func (c *Config) sendNotification(ctx context.Context, p Payload, req *http.Request) (ok bool, err error) {
	if err := c.sig.AddSignature(req); err != nil {
		return false, err
	}
	// have to copy the body out before sending the request.
	kvs := c.requestKVS(p.Task, req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		kvs = append(kvs, c.responseKVS(p.Task, resp)...)
		kvs = append(kvs, []interface{}{"host", c.Host, "task", p.Task, "consumerURL", c.ConsumerURL})
		if c.LogNotifications {
			c.Logger.Info("sent webhook notification", kvs...)
		}
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	kvs = append(kvs, c.responseKVS(p.Task, resp)...)
	kvs = append(kvs, []interface{}{"host", c.Host, "task", p.Task, "consumerURL", c.ConsumerURL})
	if c.LogNotifications {
		c.Logger.Info("sent webhook notification", kvs...)
	}
	return true, nil
}
