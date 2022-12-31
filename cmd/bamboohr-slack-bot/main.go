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
	database.Cryptokey = []byte(Conf("cryptokey"))

	go func() {
		for {
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
		s := &http.Server{
			Addr:    endpoint,
			Handler: nil,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		}
		log.Fatal(s.ListenAndServeTLS("", ""))
	} else {
		log.Infof("Starting HTTP server (%s).", endpoint)
		s := &http.Server{
			Addr:    endpoint,
			Handler: nil,
		}
		log.Fatal(s.ListenAndServe())
	}
}
