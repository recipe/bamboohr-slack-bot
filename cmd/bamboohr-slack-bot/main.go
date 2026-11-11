package main

import (
	"crypto/tls"
	"embed"
	"github.com/gookit/config"
	"github.com/gookit/config/yaml"
	"github.com/recipe/bamboohr-slack-bot/internal/database"
	log "github.com/sirupsen/logrus"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"time"
)

const PollingIntervalMin = 10
const CommandName = "whoisout"
const CommandUsage = "These are available " + CommandName + " commands:\n" +
	"`/" + CommandName + "` Get an information about teammates who are out today.\n" +
	"`/" + CommandName + "` in <department> Get the same information for people in the department.\n" +
	"`/" + CommandName + " install <org name> <api secret>` Install the BambooHR API token for your team. " +
	"`<org name>` is the name of your organization as it is used in the BambooHR API."
const SlackScope = "users.profile:write,users.profile:read,users:read.email,users:read,commands"

//go:embed templates/*
var Templates embed.FS

func init() {
	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

// Conf reads the value from the config.yml for the specific key.
func Conf(key string) string {
	v, ok := config.String(key)
	if !ok {
		log.Fatalf("The %s must be provided in the config.yml.", key)
	}

	return v
}

func main() {
	defer database.DB.Close()
	config.AddDriver(yaml.Driver)
	var err error
	ok := false
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	configDestinations := [3]string{homeDir, ".", "/etc/bamboohr-slack-bot"}
	for _, file := range configDestinations {
		err = config.LoadFiles(file + "/config.yml")
		if err == nil {
			log.Infof("Loading the %s.", file+"/config.yml")
			ok = true
			break
		}
	}
	if !ok {
		log.Fatalf("Unable to load the config.yml: %v", err)
	}

	logLevel := Conf("log_level")
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("An invalid log_level (%s) value in the config.yml.", logLevel)
	}
	log.SetLevel(level)
	cryptokey := Conf("cryptokey")
	if err := database.ValidateCryptokey(cryptokey); err != nil {
		log.Fatalf("Invalid cryptokey in the config.yml: %v", err)
	}
	database.Cryptokey = []byte(cryptokey)

	go func() {
		for {
			// Install callbacks contain BambooHR secrets, they must not outlive the installation.
			if n, err := database.PurgeExpiredInstallCallbacks(time.Now()); err != nil {
				log.Errorf("Unable to purge expired install callbacks: %v", err)
			} else if n > 0 {
				log.Infof("Purged %d expired install callback(s).", n)
			}
			err := Run()
			<-time.After(PollingIntervalMin * time.Minute)
			if err != nil {
				log.Fatalf("Status poller failed: %s.", err.Error())
			}
		}
	}()

	SSLCrt := Conf("ssl_cert")
	SSLKey := Conf("ssl_key")
	endpoint := Conf("server_endpoint")

	slackClientID := Conf("slack_client_id")
	// make sure that the values are provided
	_ = Conf("slack_client_secret")
	_ = Conf("slack_signing_secret")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		tpl := template.Must(template.ParseFS(Templates, "templates/index.html"))
		_ = tpl.Execute(w, map[string]string{
			"SlackClientID": url.QueryEscape(slackClientID),
			"SlackScope":    SlackScope,
		})
	})

	http.HandleFunc("/redirect", RedirectHandler)

	http.HandleFunc("/command", CommandHandler)

	if SSLCrt != "" && SSLKey != "" {
		log.Infof("Starting HTTPS server (%s).", endpoint)
		cert, err := tls.LoadX509KeyPair(SSLCrt, SSLKey)
		if err != nil {
			log.Fatalf("Cannot load x509 key pair: %v", err)
		}
		log.Fatal(NewServer(endpoint, &cert).ListenAndServeTLS("", ""))
	} else {
		WarnPlainHTTP(endpoint)
		log.Fatal(NewServer(endpoint, nil).ListenAndServe())
	}
}

// Server timeouts. Slow or idle clients must not be able to hold connections open indefinitely.
// The install command calls Slack and BambooHR before responding, so the write timeout leaves room for it.
const (
	ServerReadHeaderTimeout = 5 * time.Second
	ServerReadTimeout       = 15 * time.Second
	ServerWriteTimeout      = 30 * time.Second
	ServerIdleTimeout       = 2 * time.Minute
)

// NewServer creates the HTTP server. It serves HTTPS with TLS 1.2 or newer when the certificate is provided.
func NewServer(endpoint string, cert *tls.Certificate) *http.Server {
	s := &http.Server{
		Addr:              endpoint,
		Handler:           nil,
		ReadHeaderTimeout: ServerReadHeaderTimeout,
		ReadTimeout:       ServerReadTimeout,
		WriteTimeout:      ServerWriteTimeout,
		IdleTimeout:       ServerIdleTimeout,
	}
	if cert != nil {
		s.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	return s
}

// WarnPlainHTTP warns that the server is started without TLS.
func WarnPlainHTTP(endpoint string) {
	log.Warnf("Starting a plain HTTP server (%s). Slack requests, OAuth codes and BambooHR secrets "+
		"travel unencrypted unless a reverse proxy terminates TLS in front of it. "+
		"Set ssl_cert and ssl_key in the config.yml to serve HTTPS.", endpoint)
}
