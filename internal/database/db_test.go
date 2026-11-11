package database

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	Cryptokey = []byte(strings.Repeat("0123456789abcdef", 4))
	os.Exit(m.Run())
}

func TestEncryptDecrypt(t *testing.T) {
	for _, s := range []string{"", "a", `{"bamboohr_secret":"s3cr3t"}`, strings.Repeat("ü", 1000)} {
		enc := Encrypt(s)
		if s != "" && enc == s {
			t.Errorf("%q is not encrypted", s)
		}
		if got := Decrypt(enc); got != s {
			t.Errorf("got %q, want %q", got, s)
		}
	}
}

func TestAppliedStatuses(t *testing.T) {
	a := AppliedStatus{Text: "On holiday", Emoji: ":palm_tree:", Expiration: 1}
	b := AppliedStatus{Text: "Out sick", Emoji: ":face_with_thermometer:", Expiration: 2}
	for _, put := range []struct {
		team, user string
		s          AppliedStatus
	}{
		{"T1", "U1", a}, {"T1", "U2", b}, {"T10", "U3", a}, {"T2", "U1", b},
	} {
		if err := PutAppliedStatus(put.team, put.user, put.s); err != nil {
			t.Fatal(err)
		}
	}

	// Teams must not leak into each other, even when one ID is a prefix of another.
	if got := GetAppliedStatuses("T1"); !reflect.DeepEqual(got, map[string]AppliedStatus{"U1": a, "U2": b}) {
		t.Errorf("T1: got %+v", got)
	}
	if got := GetAppliedStatuses("T2"); !reflect.DeepEqual(got, map[string]AppliedStatus{"U1": b}) {
		t.Errorf("T2: got %+v", got)
	}

	if err := PutAppliedStatus("T1", "U1", b); err != nil {
		t.Fatal(err)
	}
	if err := DeleteAppliedStatus("T1", "U2"); err != nil {
		t.Fatal(err)
	}
	if got := GetAppliedStatuses("T1"); !reflect.DeepEqual(got, map[string]AppliedStatus{"U1": b}) {
		t.Errorf("T1 after update: got %+v", got)
	}
	if got := GetAppliedStatuses("T3"); len(got) != 0 {
		t.Errorf("T3: got %+v", got)
	}
}

func TestWIOMessage(t *testing.T) {
	msg := []WhoIsOutMessage{{
		Employee: WhoIsOutMessageEmployee{SlackUser: WhoIsOutMessageSlackUser{ID: "U1", RealName: "Alice"}},
		TimeOff:  TimeOff{Type: &TimeOffType{Text: "On holiday"}, Start: "2026-11-13", End: "2026-11-16"},
	}}
	if err := PutWIOMessage("T1", msg); err != nil {
		t.Fatal(err)
	}
	got, err := GetWIOMessage("T1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, msg) {
		t.Errorf("got %+v, want %+v", got, msg)
	}
}

func TestOrgs(t *testing.T) {
	org := &OrganizationCredentials{SlackTeamID: "TORG", SlackAdminUserID: "UADMIN", BambooHROrg: "acme", BambooHRSecret: "s"}
	if err := PutOrg(org); err != nil {
		t.Fatal(err)
	}
	// An organization without the admin's token is skipped.
	for _, o := range GetOrgs() {
		if o.SlackTeamID == "TORG" {
			t.Error("the organization without a token must be skipped")
		}
	}
	if err := PutSlackUserToken("TORG", "UADMIN", SlackToken{AccessToken: "xoxp"}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range GetOrgs() {
		if o.SlackTeamID == "TORG" {
			found = true
			if o.BambooHROrg != "acme" || o.SlackToken.AccessToken != "xoxp" {
				t.Errorf("unexpected organization %+v", o)
			}
		}
	}
	if !found {
		t.Error("the organization is not found")
	}
}

func TestInstallCallback(t *testing.T) {
	cb := InstallCallback{
		ResponseURL:    "https://hooks.slack.com/commands/T1/123/abc",
		BambooHROrg:    "acme",
		BambooHRSecret: "0123456789abcdef0123456789abcdef01234567",
	}
	if err := PutInstallCallback("123.456", cb); err != nil {
		t.Fatal(err)
	}

	// The secret must be encrypted at rest.
	raw, err := DB.Get([]byte(CallbackPrefix+":123.456"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), cb.BambooHRSecret) {
		t.Error("the install callback is stored unencrypted")
	}

	before := time.Now()
	got, err := GetInstallCallback("123.456")
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Unix(got.ExpiresAt, 0)
	if exp.Before(before.Add(InstallCallbackTTL-time.Minute)) || exp.After(before.Add(InstallCallbackTTL+time.Minute)) {
		t.Errorf("unexpected expiration %s", exp)
	}
	got.ExpiresAt = 0
	if *got != cb {
		t.Errorf("got %+v, want %+v", *got, cb)
	}

	if err := DeleteInstallCallback("123.456"); err != nil {
		t.Fatal(err)
	}
	if _, err := GetInstallCallback("123.456"); err == nil {
		t.Error("expected an error for a deleted callback")
	}
}

// putRawCallback stores an install callback as is, bypassing PutInstallCallback which sets the expiration.
func putRawCallback(t *testing.T, state string, cb InstallCallback) {
	t.Helper()
	b, err := json.Marshal(cb)
	if err != nil {
		t.Fatal(err)
	}
	if err := DB.Put([]byte(CallbackPrefix+":"+state), []byte(Encrypt(string(b))), nil); err != nil {
		t.Fatal(err)
	}
}

func callbackExists(t *testing.T, state string) bool {
	t.Helper()
	ok, err := DB.Has([]byte(CallbackPrefix+":"+state), nil)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestGetInstallCallbackExpiration(t *testing.T) {
	now := time.Now().Unix()
	for _, c := range []struct {
		name      string
		expiresAt int64
	}{
		{"expired", now - 1},
		{"saved before the expiration was introduced", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			putRawCallback(t, "exp", InstallCallback{BambooHRSecret: "secret", ExpiresAt: c.expiresAt})
			if _, err := GetInstallCallback("exp"); err != ErrInstallCallbackExpired {
				t.Errorf("got %v, want ErrInstallCallbackExpired", err)
			}
			if callbackExists(t, "exp") {
				t.Error("an expired callback must be removed")
			}
		})
	}

	t.Run("not expired yet", func(t *testing.T) {
		putRawCallback(t, "valid", InstallCallback{BambooHRSecret: "secret", ExpiresAt: now + 60})
		if _, err := GetInstallCallback("valid"); err != nil {
			t.Errorf("got %v", err)
		}
		_ = DeleteInstallCallback("valid")
	})
}

func TestPurgeExpiredInstallCallbacks(t *testing.T) {
	now := time.Now()
	putRawCallback(t, "p-expired", InstallCallback{ExpiresAt: now.Unix() - 1})
	putRawCallback(t, "p-legacy", InstallCallback{})
	putRawCallback(t, "p-valid", InstallCallback{ExpiresAt: now.Unix() + 60})
	if err := DB.Put([]byte(CallbackPrefix+":p-corrupted"), []byte("not base64!"), nil); err != nil {
		t.Fatal(err)
	}
	// Other records must not be touched.
	if err := PutAppliedStatus("TPURGE", "U1", AppliedStatus{Text: "On holiday"}); err != nil {
		t.Fatal(err)
	}

	n, err := PurgeExpiredInstallCallbacks(now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("purged %d callbacks, want 3", n)
	}
	for state, want := range map[string]bool{"p-expired": false, "p-legacy": false, "p-corrupted": false, "p-valid": true} {
		if got := callbackExists(t, state); got != want {
			t.Errorf("%s: exists %v, want %v", state, got, want)
		}
	}
	if len(GetAppliedStatuses("TPURGE")) != 1 {
		t.Error("other records must not be removed")
	}

	// The valid callback expires later.
	if n, _ := PurgeExpiredInstallCallbacks(now.Add(time.Minute)); n != 1 || callbackExists(t, "p-valid") {
		t.Errorf("purged %d callbacks, the valid one must expire in a minute", n)
	}
	if n, _ := PurgeExpiredInstallCallbacks(now.Add(time.Minute)); n != 0 {
		t.Errorf("nothing must be left to purge, purged %d", n)
	}
}
