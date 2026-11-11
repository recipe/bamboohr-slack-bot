package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
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
			srv := NewServer("localhost:8443", s.cert, http.NotFoundHandler())
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

func TestRoutes(t *testing.T) {
	srv := httptest.NewServer(Routes("client-id"))
	t.Cleanup(srv.Close)

	get := func(t *testing.T, path string) (*http.Response, string) {
		t.Helper()
		res, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res, string(b)
	}

	t.Run("landing page", func(t *testing.T) {
		res, body := get(t, "/")
		if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
			t.Fatalf("got HTTP %d %s", res.StatusCode, res.Header.Get("Content-Type"))
		}
		if !strings.Contains(body, "client_id=client-id") {
			t.Error("the Slack client ID is missing")
		}
		// Fixed curly quotes: the attribute must be parsed.
		if strings.Contains(body, "”") || strings.Count(body, `rel="noopener noreferrer"`) != 2 {
			t.Error(`the links must have rel="noopener noreferrer"`)
		}
		// No requests to other hosts: links and the Slack button are the only absolute URLs.
		for _, host := range []string{"unpkg.com", "fonts.googleapis.com", "fonts.gstatic.com"} {
			if strings.Contains(body, host) {
				t.Errorf("the page must not load anything from %s", host)
			}
		}
		for _, ref := range []string{`href="static/normalize.css"`, `url(static/satisfy.woff2)`} {
			if !strings.Contains(body, ref) {
				t.Errorf("%s is missing", ref)
			}
		}
	})

	t.Run("static files", func(t *testing.T) {
		for path, contentType := range map[string]string{
			"/static/normalize.css": "text/css",
			"/static/satisfy.woff2": "font/woff2",
		} {
			res, body := get(t, path)
			if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), contentType) || body == "" {
				t.Errorf("%s: got HTTP %d %s", path, res.StatusCode, res.Header.Get("Content-Type"))
			}
		}
		for _, path := range []string{"/static/missing.css", "/static/LICENSE-satisfy.txt"} {
			if res, _ := get(t, path); res.StatusCode != http.StatusNotFound {
				t.Errorf("%s: got HTTP %d", path, res.StatusCode)
			}
		}
		// Only the static folder is served, not the templates.
		if res, _ := get(t, "/templates/index.html"); res.StatusCode != http.StatusNotFound {
			t.Errorf("got HTTP %d for a template", res.StatusCode)
		}
	})

	t.Run("security headers on every response", func(t *testing.T) {
		for _, path := range []string{"/", "/static/normalize.css", "/missing", "/redirect?error=access_denied", "/command"} {
			res, _ := get(t, path)
			for header, want := range map[string]string{
				"Content-Security-Policy": ContentSecurityPolicy,
				"X-Content-Type-Options":  "nosniff",
				"Referrer-Policy":         "no-referrer",
				"X-Frame-Options":         "DENY",
			} {
				if got := res.Header.Get(header); got != want {
					t.Errorf("%s: %s is %q, want %q", path, header, got, want)
				}
			}
		}
	})
}
