package database

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
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
		if got := mustDecrypt(t, enc); got != s {
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

// v0Fixture was produced by Encrypt before the versioned encryption was introduced,
// with the test Cryptokey. It must always be readable.
const v0Fixture = "wzyAjs82QYxenMHnNFh+fWGh55wrdJ2GzhzjKMQpoKD504m7YRFTuP8JGYTZ3fEoY2xtbrz/Xc+1IsGcTgmZ3O2nG+b1AXHFe2K+t5s66gk5S5rH"

const v0FixturePlaintext = `{"bamboohr_org":"acme","bamboohr_secret":"0123456789abcdef0123456789abcdef01234567"}`

// v0Encrypt encrypts the data as Encrypt did before the versioned encryption was introduced.
func v0Encrypt(t *testing.T, data string) string {
	t.Helper()
	block, err := aes.NewCipher(v0CreateKey(Cryptokey, 32))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(data))
	v0CFB8Encrypter(block, Cryptokey[len(Cryptokey)-aes.BlockSize:]).XORKeyStream(ciphertext, []byte(data))
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// mustDecrypt decrypts the data and fails the test on an error.
func mustDecrypt(t *testing.T, data string) string {
	t.Helper()
	res, err := Decrypt(data)
	if err != nil {
		t.Fatalf("unable to decrypt %q: %v", data, err)
	}
	return res
}

func TestV0Encryption(t *testing.T) {
	if got := v0Encrypt(t, v0FixturePlaintext); got != v0Fixture {
		t.Fatalf("the v0 encryption helper doesn't match the fixture: %s", got)
	}
	if got := mustDecrypt(t, v0Fixture); got != v0FixturePlaintext {
		t.Errorf("got %q, want %q", got, v0FixturePlaintext)
	}
	for _, s := range []string{"a", strings.Repeat("ü", 1000)} {
		if got := mustDecrypt(t, v0Encrypt(t, s)); got != s {
			t.Errorf("got %q, want %q", got, s)
		}
	}
}

// v1Fixture was produced by Encrypt with the test Cryptokey. It must always be readable.
const v1Fixture = "$01$/EGPcEzppS9CvjY4$bBgsmiZQJQr+c2/mH3nZGI0+JcDiaQRs38z/bHRoeyA0BFMR5widg0aCoUB61EYVUPQakbNJlDc3br7QBZrXQ8+zSqLIjLJyD494VGDaoqy8cGFdO1moy3U9I+GGowy3yssxsg=="

func TestEncryptionV1(t *testing.T) {
	if got := mustDecrypt(t, v1Fixture); got != v0FixturePlaintext {
		t.Errorf("got %q, want %q", got, v0FixturePlaintext)
	}

	enc := Encrypt(v0FixturePlaintext)
	parts := strings.Split(enc, "$")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "01" {
		t.Fatalf("unexpected format %q", enc)
	}
	nonce, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(nonce) != 12 {
		t.Errorf("unexpected nonce %q: %v", parts[2], err)
	}
	if strings.Contains(enc, "0123456789abcdef") {
		t.Error("the value is not encrypted")
	}
	if Encrypt(v0FixturePlaintext) == enc {
		t.Error("the same value must be encrypted with a different nonce every time")
	}

	ct, _ := base64.StdEncoding.DecodeString(parts[3])
	ct[0] ^= 1
	tampered := "$01$" + parts[2] + "$" + base64.StdEncoding.EncodeToString(ct)
	otherNonce := Encrypt("x")
	for name, v := range map[string]string{
		"tampered ciphertext": tampered,
		"another nonce":       "$01$" + strings.Split(otherNonce, "$")[2] + "$" + parts[3],
		"unsupported version": "$02$" + parts[2] + "$" + parts[3],
		"missing part":        "$01$" + parts[3],
		"extra part":          enc + "$",
		"invalid base64":      "$01$!!!$" + parts[3],
		"short nonce":         "$01$" + base64.StdEncoding.EncodeToString([]byte("short")) + "$" + parts[3],
		"invalid v0 value":    "not base64!",
	} {
		if _, err := Decrypt(v); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}

	t.Run("another key", func(t *testing.T) {
		orig := Cryptokey
		t.Cleanup(func() { Cryptokey = orig })
		Cryptokey = []byte("Kq3vT9xLm2Rz8WbN4pYc7HsJd1FgA6eU0oViQ5tXhGwE3kMnB8rZyP2lCuS7aDfJ")
		if _, err := Decrypt(enc); err == nil {
			t.Error("expected an error")
		}
	})
}

func TestV0RecordsAreReadable(t *testing.T) {
	// A record saved by the previous version.
	s := AppliedStatus{Text: "On holiday", Emoji: ":palm_tree:", Expiration: 1}
	b, _ := json.Marshal(s)
	key := []byte(StatusPrefix + ":TV0:U1")
	if err := DB.Put(key, []byte(v0Encrypt(t, string(b))), nil); err != nil {
		t.Fatal(err)
	}
	if got := GetAppliedStatuses("TV0"); got["U1"] != s {
		t.Fatalf("got %+v, want %+v", got, s)
	}

	// Once the record is saved again, it's encrypted with the latest scheme.
	if err := PutAppliedStatus("TV0", "U1", s); err != nil {
		t.Fatal(err)
	}
	raw, err := DB.Get(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), "$01$") {
		t.Errorf("unexpected format %q", raw)
	}
	if got := GetAppliedStatuses("TV0"); got["U1"] != s {
		t.Errorf("got %+v, want %+v", got, s)
	}
}

func TestCreateKey(t *testing.T) {
	// Computed independently with RFC 5869 HKDF-SHA256 for the test Cryptokey, without a salt and info.
	// If it changes, records encrypted with v1 can't be decrypted anymore.
	const want = "2deaccaffc6f5754afa4d85467340199703a9ab1a7c7fd9c1cf61aa65fe4ae19"
	key, err := createKey(Cryptokey, 32)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(key) != want {
		t.Errorf("got %x, want %s", key, want)
	}

	// The test Cryptokey is made of two equal halves, which the v0 XOR-folding turns into all zeros.
	if !bytes.Equal(v0CreateKey(Cryptokey, 32), make([]byte, 32)) {
		t.Error("v0CreateKey must not change")
	}
	if bytes.Equal(key, make([]byte, 32)) {
		t.Error("the v1 key must not be all zeros")
	}

	other, err := createKey([]byte(strings.Repeat("fedcba9876543210", 4)), 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(key, other) {
		t.Error("different cryptokeys must produce different keys")
	}
}

func TestValidateCryptokey(t *testing.T) {
	for _, c := range []struct {
		name  string
		key   string
		valid bool
	}{
		{"the postinst default: openssl rand -base64 48", "Kq3vT9xLm2Rz8WbN4pYc7HsJd1FgA6eU0oViQ5tXhGwE3kMnB8rZyP2lCuS7aDfJ", true},
		{"minimum length", strings.Repeat("k", MinCryptokeyLength), true},
		{"too short", strings.Repeat("k", MinCryptokeyLength-1), false},
		{"empty", "", false},
		{"sample placeholder", SampleCryptokey, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateCryptokey(c.key)
			if (err == nil) != c.valid {
				t.Errorf("got %v, want valid=%v", err, c.valid)
			}
			if err != nil && c.key != "" && strings.Contains(err.Error(), c.key) {
				t.Errorf("the error must not reveal the key: %v", err)
			}
		})
	}
}

func TestSampleCryptokeyIsDetected(t *testing.T) {
	b, err := os.ReadFile("../../config.yml-sample")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "cryptokey: \""+SampleCryptokey+"\"") {
		t.Errorf("the cryptokey placeholder in config.yml-sample must be %q", SampleCryptokey)
	}
}

func TestCorruptedRecords(t *testing.T) {
	corrupted := map[string][]byte{
		"invalid base64":    []byte("not base64!"),
		"tampered v1 value": []byte("$01$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		"not JSON":          []byte(Encrypt("not JSON")),
	}

	t.Run("an organization with corrupted credentials is skipped", func(t *testing.T) {
		good := &OrganizationCredentials{SlackTeamID: "TGOOD", SlackAdminUserID: "UADMIN", BambooHROrg: "acme"}
		if err := PutOrg(good); err != nil {
			t.Fatal(err)
		}
		if err := PutSlackUserToken("TGOOD", "UADMIN", SlackToken{AccessToken: "xoxp"}); err != nil {
			t.Fatal(err)
		}
		for name, v := range corrupted {
			if err := DB.Put([]byte(TeamPrefix+":TBAD-"+strings.ReplaceAll(name, " ", "-")), v, nil); err != nil {
				t.Fatal(err)
			}
		}
		found := false
		for _, o := range GetOrgs() {
			if strings.HasPrefix(o.SlackTeamID, "TBAD") {
				t.Errorf("a corrupted organization is returned: %+v", o)
			}
			if o.SlackTeamID == "TGOOD" && o.SlackToken.AccessToken == "xoxp" {
				found = true
			}
		}
		if !found {
			t.Error("the valid organization must still be returned")
		}
	})

	t.Run("a corrupted user token is not found", func(t *testing.T) {
		for name, v := range corrupted {
			if err := DB.Put([]byte(UserPrefix+":UBAD:TBAD"), v, nil); err != nil {
				t.Fatal(err)
			}
			if _, ok := GetSlackUserToken("TBAD", "UBAD"); ok {
				t.Errorf("%s: a corrupted token must not be returned", name)
			}
		}
	})

	t.Run("other records", func(t *testing.T) {
		for name, v := range corrupted {
			_ = DB.Put([]byte(WhoIsOutPrefix+":TBAD"), v, nil)
			if _, err := GetWIOMessage("TBAD"); err == nil {
				t.Errorf("%s: expected an error for the who-is-out message", name)
			}
			_ = DB.Put([]byte(DepartmentsPrefix+":TBAD"), v, nil)
			if _, ok := GetOrgDepartments("TBAD"); ok {
				t.Errorf("%s: corrupted departments must not be returned", name)
			}
			_ = DB.Put([]byte(StatusPrefix+":TBAD:U1"), v, nil)
			if got := GetAppliedStatuses("TBAD"); len(got) != 0 {
				t.Errorf("%s: corrupted statuses must be skipped: %+v", name, got)
			}
			_ = DB.Put([]byte(CallbackPrefix+":bad"), v, nil)
			if _, err := GetInstallCallback("bad"); err == nil {
				t.Errorf("%s: expected an error for the install callback", name)
			}
		}
		_ = DB.Delete([]byte(CallbackPrefix+":bad"), nil)
	})
}
