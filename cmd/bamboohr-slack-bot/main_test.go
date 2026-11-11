package main

import (
	"crypto/tls"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

// captureLogs captures log entries of the test at the debug level.
func captureLogs(t *testing.T) *logtest.Hook {
	t.Helper()
	hook := logtest.NewGlobal()
	level := log.GetLevel()
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() {
		log.SetLevel(level)
		log.StandardLogger().ReplaceHooks(make(log.LevelHooks))
	})
	return hook
}

func TestNewServer(t *testing.T) {
	cert := tls.Certificate{Certificate: [][]byte{{1}}}
	for name, s := range map[string]struct {
		cert *tls.Certificate
	}{
		"HTTP":  {nil},
		"HTTPS": {&cert},
	} {
		t.Run(name, func(t *testing.T) {
			srv := NewServer("localhost:8443", s.cert)
			if srv.Addr != "localhost:8443" {
				t.Errorf("unexpected address %s", srv.Addr)
			}
			if srv.ReadHeaderTimeout != ServerReadHeaderTimeout || srv.ReadTimeout != ServerReadTimeout ||
				srv.WriteTimeout != ServerWriteTimeout || srv.IdleTimeout != ServerIdleTimeout {
				t.Errorf("timeouts are not set: %+v", srv)
			}
			for _, d := range []struct {
				name  string
				value int64
			}{
				{"ReadHeaderTimeout", int64(srv.ReadHeaderTimeout)},
				{"ReadTimeout", int64(srv.ReadTimeout)},
				{"WriteTimeout", int64(srv.WriteTimeout)},
				{"IdleTimeout", int64(srv.IdleTimeout)},
			} {
				if d.value <= 0 {
					t.Errorf("%s must be positive", d.name)
				}
			}
			if s.cert == nil {
				if srv.TLSConfig != nil {
					t.Error("plain HTTP must not have a TLS config")
				}
				return
			}
			if srv.TLSConfig == nil || srv.TLSConfig.MinVersion != tls.VersionTLS12 {
				t.Fatalf("TLS 1.2 must be the minimum version: %+v", srv.TLSConfig)
			}
			if len(srv.TLSConfig.Certificates) != 1 || srv.TLSConfig.Certificates[0].Certificate[0][0] != 1 {
				t.Error("the certificate is not set")
			}
		})
	}

	// The install command is processed before the response is written, with 10 s timeouts per API call.
	if ServerWriteTimeout < ServerReadTimeout {
		t.Error("the write timeout must leave room for the install command")
	}
}

func TestIsLoopbackEndpoint(t *testing.T) {
	for endpoint, want := range map[string]bool{
		"127.0.0.1:8087":   true,
		"127.0.0.2:8087":   true,
		"[::1]:8087":       true,
		"localhost:8087":   true,
		":8087":            false,
		"0.0.0.0:8087":     false,
		"[::]:8087":        false,
		"10.18.0.6:8443":   false,
		"203.0.113.5:443":  false,
		"example.com:443":  false,
		"localhost":        false,
		"":                 false,
		"127.0.0.1.evil:1": false,
	} {
		if got := IsLoopbackEndpoint(endpoint); got != want {
			t.Errorf("%q: got %v, want %v", endpoint, got, want)
		}
	}
}

func TestWarnPlainHTTP(t *testing.T) {
	t.Run("reachable from other hosts", func(t *testing.T) {
		hook := captureLogs(t)
		WarnPlainHTTP("10.18.0.6:8443")
		e := hook.LastEntry()
		if e == nil || e.Level != log.WarnLevel || !strings.Contains(e.Message, "plain HTTP") ||
			!strings.Contains(e.Message, "10.18.0.6:8443") || !strings.Contains(e.Message, "ssl_cert") {
			t.Errorf("unexpected log entry %+v", e)
		}
	})

	t.Run("loopback behind a reverse proxy", func(t *testing.T) {
		hook := captureLogs(t)
		WarnPlainHTTP("127.0.0.1:8087")
		for _, e := range hook.AllEntries() {
			if e.Level <= log.WarnLevel {
				t.Errorf("unexpected warning %+v", e)
			}
		}
		if e := hook.LastEntry(); e == nil || !strings.Contains(e.Message, "127.0.0.1:8087") {
			t.Errorf("the server start must be logged: %+v", e)
		}
	})
}
