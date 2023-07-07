package bmc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog"
)

func TestOpen(t *testing.T) {
	tests := map[string]struct {
		url       string
		shouldErr bool
	}{
		"success":        {},
		"bad url":        {url: "%", shouldErr: true},
		"failed request": {url: "127.1.1.1", shouldErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("{'data': 'dummy'}"))
			}))
			defer svr.Close()

			u := svr.URL
			if tc.url != "" {
				u = tc.url
			}
			c := New(u, "127.0.1.1")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := c.Open(ctx); err != nil && !tc.shouldErr {
				t.Fatal(err)
			}
		})
	}
}

func TestBootDeviceSet(t *testing.T) {
	tests := map[string]struct {
		url       string
		shouldErr bool
	}{
		"success":        {},
		"failed request": {url: "127.1.1.1", shouldErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("{'data': 'dummy'}"))
			}))
			defer svr.Close()

			u := svr.URL
			if tc.url != "" {
				u = tc.url
			}
			c := New(u, "127.0.1.1")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_ = c.Open(ctx)
			if _, err := c.BootDeviceSet(ctx, "pxe", false, false); err != nil && !tc.shouldErr {
				t.Fatal(err)
			}
		})
	}
}

func TestPowerSet(t *testing.T) {
	tests := map[string]struct {
		url        string
		powerState string
		shouldErr  bool
	}{
		"success":        {},
		"failed request": {url: "127.1.1.1", shouldErr: true},
		"unknown state":  {powerState: "unknown", shouldErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("{'data': 'dummy'}"))
			}))
			defer svr.Close()

			u := svr.URL
			if tc.url != "" {
				u = tc.url
			}
			c := New(u, "127.0.1.1")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_ = c.Open(ctx)
			state := tc.powerState
			if state == "" {
				state = "on"
			}
			if _, err := c.PowerSet(ctx, state); err != nil && !tc.shouldErr {
				t.Fatal(err)
			}
		})
	}
}

func TestPowerStateGet(t *testing.T) {
	tests := map[string]struct {
		powerState string
		shouldErr  bool
	}{
		"success":       {},
		"unknown state": {shouldErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			c := New("localhost", "127.0.1.1")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_ = c.Open(ctx)
			state := "on"
			if tc.shouldErr {
				state = ""
			}
			c.powerState = state
			got, err := c.PowerStateGet(ctx)
			if err != nil && !tc.shouldErr {
				t.Fatal(err)
			} else if got != state {
				t.Fatalf("expected %s, got %s", state, got)
			}
		})
	}
}

func TestBootDevice(t *testing.T) {
	/*run := os.Getenv("LIVE_TEST")
	if run == "" {
		t.Skip("set LIVE_TEST to run this test")
	}*/
	c := New("https://webhook.weinstocklabs.com/webhook", "192.168.2.3")
	c.Logger = defaultLogger("info")
	c.AddSecrets(map[Algorithm][]string{SHA256: {"superSecret1", "superSecret2"}, SHA512: {"superSecret1", "superSecret2"}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Open(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	ok, err := c.BootDeviceSet(ctx, "pxe", false, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("BootDeviceSet ok: %v", ok)

	st, err := c.PowerSet(ctx, "on")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("powerSet: %v", st)

	s, err := c.PowerStateGet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("powerState: %v", s)

	st, err = c.PowerSet(ctx, "off")
	if err != nil {
		t.Error(err)
	}
	t.Logf("powerSet: %v", st)

	s, err = c.PowerStateGet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("powerState: %v", s)

	t.Fatal("manual testing")
}

// defaultLogger is a zerolog logr implementation.
func defaultLogger(level string) logr.Logger {
	zl := zerolog.New(os.Stdout)
	zl = zl.With().Caller().Timestamp().Logger()
	var l zerolog.Level
	switch level {
	case "debug":
		l = zerolog.DebugLevel
	default:
		l = zerolog.InfoLevel
	}
	zl = zl.Level(l)

	return zerologr.New(&zl)
}

func TestXxx(t *testing.T) {
	// run := os.Getenv("LIVE_TEST")
	// if run == "" {
	//		t.Skip("set LIVE_TEST to run this test")
	//	}
	// instantiate
	c := New("https://webhook.weinstocklabs.com/webhook", "192.168.5.6")

	// initialize
	c.Logger = defaultLogger("info")
	c.AddSecrets(map[Algorithm][]string{SHA256: {"superSecret1", "asfd"}, SHA512: {"superSecret2", "asfd"}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Open(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	ok, err := c.BootDeviceSet(ctx, "pxe", false, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("BootDeviceSet ok: %v", ok)
	t.Fail()
}
