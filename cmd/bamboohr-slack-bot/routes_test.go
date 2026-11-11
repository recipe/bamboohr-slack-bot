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
	bodies   []string
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
		r.bodies = append(r.bodies, string(b))
		r.mu.Unlock()
	}))
	t.Cleanup(r.Close)
	return r
}

type processCall struct {
	cb           database.InstallCallback
	team, user   string
	requestToken bool
}

// stubProcessInstall replaces the installation processing which calls Slack and BambooHR.
func stubProcessInstall(t *testing.T) *[]processCall {
	t.Helper()
	calls := &[]processCall{}
	orig := processInstall
	processInstall = func(cb database.InstallCallback, team, user string, requestToken bool) {
		*calls = append(*calls, processCall{cb, team, user, requestToken})
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

		if len(*calls) != 1 {
			t.Fatalf("got %+v", *calls)
		}
		got := (*calls)[0]
		if got.cb.ExpiresAt <= time.Now().Unix() {
			t.Errorf("unexpected expiration %d", got.cb.ExpiresAt)
		}
		got.cb.ExpiresAt = 0
		if got != (processCall{cb, "T1", "U1", false}) {
			t.Errorf("got %+v", got)
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

	t.Run("an expired callback is not processed", func(t *testing.T) {
		calls := stubProcessInstall(t)
		resp := newResponseURL(t)
		putExpiredCallback(t, "s4", database.InstallCallback{SlackTeamID: "T1", SlackUserID: "U1", ResponseURL: resp.URL})

		FinishInstall("s4", "T1", "U1")

		if len(*calls) != 0 {
			t.Errorf("the installation must not be processed: %+v", *calls)
		}
		expectDeleted(t, "s4")
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
	r := httptest.NewRequest(http.MethodPost, "/command", strings.NewReader(body))
	r.Header.Set("X-Slack-Request-Timestamp", ts)
	r.Header.Set("X-Slack-Signature", slackSignature("signing-secret", ts, body))
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

func TestNewState(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		s, err := NewState()
		if err != nil {
			t.Fatal(err)
		}
		// 32 random bytes, URL-safe
		if len(s) != 43 || url.QueryEscape(s) != s {
			t.Errorf("unexpected state %q", s)
		}
		if seen[s] {
			t.Fatalf("the state %q is repeated", s)
		}
		seen[s] = true
	}
}

// buttonState extracts the OAuth state from the "Review Permissions" button posted to the response URL.
func buttonState(t *testing.T, body string) string {
	t.Helper()
	var m struct {
		Attachments []struct {
			Actions []struct {
				URL string `json:"url"`
			} `json:"actions"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("unexpected message %s: %v", body, err)
	}
	if len(m.Attachments) != 1 || len(m.Attachments[0].Actions) != 1 {
		t.Fatalf("no button in %s", body)
	}
	u, err := url.Parse(m.Attachments[0].Actions[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "slack.com" || u.Query().Get("client_id") != "client-id" {
		t.Errorf("unexpected button URL %s", u)
	}
	return u.Query().Get("state")
}

func TestInstallCommandRequestsPermissionsWithRandomState(t *testing.T) {
	loadTestConfig(t, "slack_client_id: \"client-id\"\n")
	resp := newResponseURL(t)
	cb := database.InstallCallback{
		SlackTeamID:    "TSTATE",
		SlackUserID:    "U1",
		ResponseURL:    resp.URL,
		BambooHROrg:    "acme",
		BambooHRSecret: "0123456789abcdef0123456789abcdef01234567",
	}

	// The user hasn't authorized the app yet, so the permissions are requested.
	ProcessInstallCommand(cb, "TSTATE", "U1", true)
	ProcessInstallCommand(cb, "TSTATE", "U1", true)

	if len(resp.bodies) != 2 {
		t.Fatalf("got messages %v", resp.bodies)
	}
	s1, s2 := buttonState(t, resp.bodies[0]), buttonState(t, resp.bodies[1])
	if len(s1) != 43 || s1 == s2 {
		t.Errorf("the states must be random: %q, %q", s1, s2)
	}
	for _, s := range []string{s1, s2} {
		got, err := database.GetInstallCallback(s)
		if err != nil {
			t.Fatalf("no install callback for the state %q: %v", s, err)
		}
		got.ExpiresAt = 0
		if *got != cb {
			t.Errorf("got %+v, want %+v", *got, cb)
		}
		_ = database.DeleteInstallCallback(s)
	}
}

// putExpiredCallback stores an install callback which expired a second ago.
// PutInstallCallback always sets a future expiration, so the record is written directly.
func putExpiredCallback(t *testing.T, state string, cb database.InstallCallback) {
	t.Helper()
	cb.ExpiresAt = time.Now().Unix() - 1
	b, err := json.Marshal(cb)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.DB.Put([]byte(database.CallbackPrefix+":"+state), []byte(database.Encrypt(string(b))), nil); err != nil {
		t.Fatal(err)
	}
}

// slackSignature signs the request body as Slack does.
func slackSignature(secret, ts, body string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte("v0:" + ts + ":" + body))
	return "v0=" + hex.EncodeToString(h.Sum(nil))
}

func TestVerifySlackSignature(t *testing.T) {
	const secret, ts, body = "signing-secret", "1794425398", "team_id=T1&text=help"
	valid := slackSignature(secret, ts, body)
	hexMAC := strings.TrimPrefix(valid, "v0=")
	// The last hex digit replaced with another hex digit, so only the MAC comparison can reject it.
	lastDigit := "0"
	if strings.HasSuffix(valid, "0") {
		lastDigit = "1"
	}
	oneDigitDiffers := valid[:len(valid)-1] + lastDigit
	for _, c := range []struct {
		name, secret, ts, body, sig string
		want                        bool
	}{
		{"valid", secret, ts, body, valid, true},
		{"upper case hex", secret, ts, body, "v0=" + strings.ToUpper(hexMAC), true},
		{"another secret", "another-secret", ts, body, valid, false},
		{"tampered body", secret, ts, body + "&x=1", valid, false},
		{"another timestamp", secret, "1794425399", body, valid, false},
		{"one digit differs", secret, ts, body, oneDigitDiffers, false},
		{"truncated", secret, ts, body, valid[:len(valid)-2], false},
		{"missing prefix", secret, ts, body, hexMAC, false},
		{"unknown version", secret, ts, body, "v1=" + hexMAC, false},
		{"not hex", secret, ts, body, "v0=" + strings.Repeat("zz", 32), false},
		{"empty MAC", secret, ts, body, "v0=", false},
		{"empty", secret, ts, body, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := VerifySlackSignature(c.secret, c.ts, []byte(c.body), c.sig); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestCommandHandlerRejectsInvalidSignature(t *testing.T) {
	loadTestConfig(t, "slack_signing_secret: \"signing-secret\"\n")
	calls := stubProcessInstall(t)
	body := url.Values{
		"team_id": {"T1"}, "user_id": {"U1"}, "response_url": {"https://hooks.slack.com/x"},
		"text": {"install acme 0123456789abcdef0123456789abcdef01234567"},
	}.Encode()
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	r := httptest.NewRequest(http.MethodPost, "/command", strings.NewReader(body))
	r.Header.Set("X-Slack-Request-Timestamp", ts)
	r.Header.Set("X-Slack-Signature", slackSignature("another-secret", ts, body))
	w := httptest.NewRecorder()

	CommandHandler(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("got HTTP %d, want 403", w.Code)
	}
	if len(*calls) != 0 {
		t.Errorf("the command must not be processed: %+v", *calls)
	}
}

func TestCommandHandlerRequestAge(t *testing.T) {
	loadTestConfig(t, "slack_signing_secret: \"signing-secret\"\n")
	body := url.Values{
		"team_id": {"T1"}, "user_id": {"U1"}, "response_url": {"https://hooks.slack.com/x"},
		"text": {"install acme 0123456789abcdef0123456789abcdef01234567"},
	}.Encode()
	max := int64(MaxRequestAge.Seconds())
	for _, c := range []struct {
		name      string
		age       int64
		processed bool
	}{
		{"now", 0, true},
		{"within the limit", max - 5, true},
		{"from the future within the limit", -(max - 5), true},
		{"too old", max + 5, false},
		{"too far in the future", -(max + 5), false},
		{"an hour old", 3600, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			calls := stubProcessInstall(t)
			// The request is signed correctly, only the timestamp matters.
			ts := strconv.FormatInt(time.Now().Unix()-c.age, 10)
			r := httptest.NewRequest(http.MethodPost, "/command", strings.NewReader(body))
			r.Header.Set("X-Slack-Request-Timestamp", ts)
			r.Header.Set("X-Slack-Signature", slackSignature("signing-secret", ts, body))
			w := httptest.NewRecorder()

			CommandHandler(w, r)

			if processed := len(*calls) == 1; processed != c.processed {
				t.Errorf("got HTTP %d, processed %v, want %v", w.Code, processed, c.processed)
			}
			if !c.processed && w.Code != http.StatusForbidden {
				t.Errorf("got HTTP %d, want 403", w.Code)
			}
		})
	}
}

func TestCommandHandlerBodyLimit(t *testing.T) {
	loadTestConfig(t, "slack_signing_secret: \"signing-secret\"\n")
	base := url.Values{
		"team_id": {"T1"}, "user_id": {"U1"}, "response_url": {"https://hooks.slack.com/x"},
		"text": {"install acme 0123456789abcdef0123456789abcdef01234567"},
	}.Encode()
	// pad makes the body exactly the given size with an extra form field.
	pad := func(size int) string {
		const name = "&padding="
		return base + name + strings.Repeat("x", size-len(base)-len(name))
	}
	for _, c := range []struct {
		name      string
		size      int
		processed bool
	}{
		{"at the limit", MaxCommandBodyBytes, true},
		{"over the limit", MaxCommandBodyBytes + 1, false},
		{"far over the limit", 10 << 20, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			calls := stubProcessInstall(t)
			body := pad(c.size)
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			r := httptest.NewRequest(http.MethodPost, "/command", strings.NewReader(body))
			r.Header.Set("X-Slack-Request-Timestamp", ts)
			r.Header.Set("X-Slack-Signature", slackSignature("signing-secret", ts, body))
			w := httptest.NewRecorder()

			CommandHandler(w, r)

			if processed := len(*calls) == 1; processed != c.processed {
				t.Errorf("got HTTP %d, processed %v, want %v", w.Code, processed, c.processed)
			}
			if !c.processed && w.Code != http.StatusRequestEntityTooLarge {
				t.Errorf("got HTTP %d, want 413", w.Code)
			}
		})
	}
}
