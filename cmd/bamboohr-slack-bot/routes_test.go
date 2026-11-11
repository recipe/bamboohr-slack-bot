package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/recipe/bamboohr-slack-bot/internal/database"
)

// responseURL is a fake Slack response URL which records posted messages.
type responseURL struct {
	*httptest.Server
	mu       sync.Mutex
	messages []string
}

func newResponseURL(t *testing.T) *responseURL {
	t.Helper()
	r := &responseURL{}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		var m map[string]string
		_ = json.Unmarshal(b, &m)
		r.mu.Lock()
		r.messages = append(r.messages, m["text"])
		r.mu.Unlock()
	}))
	t.Cleanup(r.Close)
	return r
}

type processCall struct {
	cb                    database.InstallCallback
	triggerID, team, user string
	requestToken          bool
}

// stubProcessInstall replaces the installation processing which calls Slack and BambooHR.
func stubProcessInstall(t *testing.T) *[]processCall {
	t.Helper()
	calls := &[]processCall{}
	orig := processInstall
	processInstall = func(cb database.InstallCallback, triggerID, team, user string, requestToken bool) {
		*calls = append(*calls, processCall{cb, triggerID, team, user, requestToken})
	}
	t.Cleanup(func() { processInstall = orig })
	return calls
}

func TestFinishInstall(t *testing.T) {
	newCallback := func(t *testing.T, state string, teamID, userID, url string) database.InstallCallback {
		t.Helper()
		cb := database.InstallCallback{
			SlackTeamID:    teamID,
			SlackUserID:    userID,
			ResponseURL:    url,
			BambooHROrg:    "acme",
			BambooHRSecret: "0123456789abcdef0123456789abcdef01234567",
		}
		if err := database.PutInstallCallback(state, cb); err != nil {
			t.Fatal(err)
		}
		return cb
	}
	expectDeleted := func(t *testing.T, state string) {
		t.Helper()
		if _, err := database.GetInstallCallback(state); err == nil {
			t.Error("the install callback must be removed")
		}
	}

	t.Run("the same user in the same workspace finishes the installation", func(t *testing.T) {
		calls := stubProcessInstall(t)
		resp := newResponseURL(t)
		cb := newCallback(t, "s1", "T1", "U1", resp.URL)

		FinishInstall("s1", "T1", "U1")

		if len(*calls) != 1 || (*calls)[0] != (processCall{cb, "s1", "T1", "U1", false}) {
			t.Errorf("got %+v", *calls)
		}
		if len(resp.messages) != 0 {
			t.Errorf("unexpected messages %v", resp.messages)
		}
		expectDeleted(t, "s1")
	})

	for _, c := range []struct {
		name, team, user string
	}{
		{"another user in the same workspace", "T1", "U2"},
		{"the same user ID in another workspace", "T2", "U1"},
		{"another user in another workspace", "T2", "U2"},
	} {
		t.Run(c.name+" is rejected", func(t *testing.T) {
			calls := stubProcessInstall(t)
			resp := newResponseURL(t)
			newCallback(t, "s2", "T1", "U1", resp.URL)

			FinishInstall("s2", c.team, c.user)

			if len(*calls) != 0 {
				t.Errorf("the installation must not be processed: %+v", *calls)
			}
			// The user who ran the install command is notified.
			if len(resp.messages) != 1 || !strings.Contains(resp.messages[0], "has not been finished") {
				t.Errorf("unexpected messages %v", resp.messages)
			}
			expectDeleted(t, "s2")
		})
	}

	t.Run("a callback saved before the IDs were stored is rejected", func(t *testing.T) {
		calls := stubProcessInstall(t)
		resp := newResponseURL(t)
		newCallback(t, "s3", "", "", resp.URL)

		FinishInstall("s3", "T1", "U1")

		if len(*calls) != 0 {
			t.Errorf("the installation must not be processed: %+v", *calls)
		}
		expectDeleted(t, "s3")
	})

	t.Run("no callback", func(t *testing.T) {
		calls := stubProcessInstall(t)

		FinishInstall("unknown", "T1", "U1")

		if len(*calls) != 0 {
			t.Errorf("got %+v", *calls)
		}
	})
}

func TestInstallCommandStoresTheRequester(t *testing.T) {
	loadTestConfig(t, "slack_signing_secret: \"signing-secret\"\n")
	calls := stubProcessInstall(t)

	body := url.Values{
		"team_id":      {"T1"},
		"user_id":      {"U1"},
		"trigger_id":   {"123.456"},
		"response_url": {"https://hooks.slack.com/commands/T1/123/abc"},
		"command":      {"/whoisout"},
		"text":         {"install acme 0123456789abcdef0123456789abcdef01234567"},
	}.Encode()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	h := hmac.New(sha256.New, []byte("signing-secret"))
	h.Write([]byte("v0:" + ts + ":" + body))
	r := httptest.NewRequest(http.MethodPost, "/command", strings.NewReader(body))
	r.Header.Set("X-Slack-Request-Timestamp", ts)
	r.Header.Set("X-Slack-Signature", "v0="+hex.EncodeToString(h.Sum(nil)))
	w := httptest.NewRecorder()

	CommandHandler(w, r)

	if len(*calls) != 1 {
		t.Fatalf("got HTTP %d, calls %+v", w.Code, *calls)
	}
	c := (*calls)[0]
	if c.cb.SlackTeamID != "T1" || c.cb.SlackUserID != "U1" || c.cb.BambooHROrg != "acme" || !c.requestToken {
		t.Errorf("unexpected install callback %+v", c)
	}
}
