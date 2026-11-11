package database

import (
	"os"
	"reflect"
	"strings"
	"testing"
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

	got, err := GetInstallCallback("123.456")
	if err != nil {
		t.Fatal(err)
	}
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
