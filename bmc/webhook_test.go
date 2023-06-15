package bmc

import (
	"context"
	"os"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog"
)

func TestBootDevice(t *testing.T) {
	opts := []Option{
		WithSecrets(map[Algorithm][]string{SHA256: {"superSecret1"}}),
		WithLogger(defaultLogger("info")),
	}
	c := New("https://webhook.weinstocklabs.com/webhook", "192.168.2.3", opts...)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Open(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
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

	t.Fatal("manual testing")
}

// defaultLogger is a zerolog logr implementation.
func defaultLogger(level string) logr.Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	zerologr.NameFieldName = "logger"
	zerologr.NameSeparator = "/"

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
