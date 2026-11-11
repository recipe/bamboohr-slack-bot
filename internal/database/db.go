package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/recipe/bamboohr-slack-bot/internal/bamboohr"
	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"github.com/syndtr/goleveldb/leveldb/util"
	"golang.org/x/sys/unix"
	"strings"
	"testing"
	"time"
)

const (
	TeamPrefix        = "TEAM"
	UserPrefix        = "USER"
	WhoIsOutPrefix    = "WIO"
	CallbackPrefix    = "CALLBACK"
	DepartmentsPrefix = "DEPARTMENTS"
	StatusPrefix      = "STATUS"
)

var DB = New()
var Cryptokey []byte

type OrganizationCredentials struct {
	SlackTeamID      string     `json:"-"`
	SlackAdminUserID string     `json:"admin_user"`
	SlackToken       SlackToken `json:"-"`
	BambooHROrg      string     `json:"bamboohr_org"`
	BambooHRSecret   string     `json:"bamboohr_secret"`
}

type SlackToken slack.OAuthResponse

type InstallCallback struct {
	// The workspace and the user who ran the install command. Only they can finish the installation.
	SlackTeamID    string `json:"slack_team_id"`
	SlackUserID    string `json:"slack_user_id"`
	ResponseURL    string `json:"response_url"`
	BambooHROrg    string `json:"bamboohr_org"`
	BambooHRSecret string `json:"bamboohr_secret"`
	// Unix time after which the callback can't be used. It's set when the callback is saved.
	ExpiresAt int64 `json:"expires_at"`
}

// InstallCallbackTTL is how long the user has to authorize the app to finish the installation.
const InstallCallbackTTL = 10 * time.Minute

// ErrInstallCallbackExpired is returned for an install callback that has expired.
var ErrInstallCallbackExpired = errors.New("the install callback has expired")

// TimeOffType struct is used as the config definition
type TimeOffType struct {
	OrderNumber  int    `json:"orderNumber"`
	BambooHRType string `json:"bambooHRType"`
	Text         string `json:"text"`
	Icon         string `json:"icon"`
}

type TimeOff struct {
	Type  *TimeOffType `json:"type"`
	Start string       `json:"start"`
	End   string       `json:"end"`
}

type WhoIsOutMessageSlackUser struct {
	ID       string `json:"id"`
	RealName string `json:"realName"`
}

type WhoIsOutMessageEmployee struct {
	SlackUser WhoIsOutMessageSlackUser `json:"slack"`
	Info      *bamboohr.EmployeeInfo   `json:"info,omitempty"`
}

// WhoIsOutMessage is used to parse the who-is-out message
type WhoIsOutMessage struct {
	Employee WhoIsOutMessageEmployee `json:"employee"`
	TimeOff  TimeOff                 `json:"timeOff"`
}

// DepartmentCache represents the list of departments in cache
type DepartmentCache struct {
	Departments map[int]string `json:"departments"`
	ExpiresAt   int64          `json:"expiresAt"`
}

// AppliedStatus is a Slack profile status that has been set by the bot.
// It is used to detect statuses that must be cleared when a time off is withdrawn.
type AppliedStatus struct {
	Text       string `json:"text"`
	Emoji      string `json:"emoji"`
	Expiration int64  `json:"expiration"`
}

type cfb8 struct {
	b         cipher.Block
	blockSize int
	in        []byte
	out       []byte

	decrypt bool
}

func (x *cfb8) XORKeyStream(dst, src []byte) {
	for i := range src {
		x.b.Encrypt(x.out, x.in)
		copy(x.in[:x.blockSize-1], x.in[1:])
		if x.decrypt {
			x.in[x.blockSize-1] = src[i]
		}
		dst[i] = src[i] ^ x.out[0]
		if !x.decrypt {
			x.in[x.blockSize-1] = dst[i]
		}
	}
}

// v0CFB8Encrypter returns the encrypting AES-CFB8 stream of the v0 encryption scheme.
//
// Deprecated: v0 is only used to read records saved before the versioned encryption was introduced.
func v0CFB8Encrypter(block cipher.Block, iv []byte) cipher.Stream {
	return v0CFB8(block, iv, false)
}

// v0CFB8Decrypter returns the decrypting AES-CFB8 stream of the v0 encryption scheme.
//
// Deprecated: v0 is only used to read records saved before the versioned encryption was introduced.
func v0CFB8Decrypter(block cipher.Block, iv []byte) cipher.Stream {
	return v0CFB8(block, iv, true)
}

// v0CFB8 returns the AES-CFB8 stream of the v0 encryption scheme.
//
// Deprecated: v0 is only used to read records saved before the versioned encryption was introduced.
func v0CFB8(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		// stack trace will indicate whether it was de or encryption
		panic("cipher.newCFB: IV length must equal block size")
	}
	x := &cfb8{
		b:         block,
		blockSize: blockSize,
		out:       make([]byte, blockSize),
		in:        make([]byte, blockSize),
		decrypt:   decrypt,
	}
	copy(x.in, iv)

	return x
}

func New() (db *leveldb.DB) {
	if testing.Testing() {
		// Tests must never touch the real database.
		db, err := leveldb.Open(storage.NewMemStorage(), nil)
		if err != nil {
			log.Fatalf("Unable to open the in-memory database: %v", err)
		}

		return db
	}
	var path string
	for _, p := range [2]string{"/opt/bamboohr-slack-bot/db", "."} {
		if unix.Access(p, unix.W_OK) == nil {
			path = p + "/bsdb"

			break
		}
	}
	log.Infof("Opening the database using the (%s) path.", path)
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		log.Fatalf("Unable to open the database file %s.", path)
	}

	return
}

// createKey derives the encryption key of the specified size from the cryptokey with HKDF-SHA256.
func createKey(key []byte, keySize int) ([]byte, error) {
	return hkdf.Key(sha256.New, key, nil, "", keySize)
}

// v0CreateKey derives the encryption key of the v0 scheme by XOR-folding the cryptokey into the key size.
//
// Deprecated: v0 is only used to read records saved before the versioned encryption was introduced.
func v0CreateKey(key []byte, keySize int) (result []byte) {
	l := len(key)
	result = make([]byte, keySize)
	for i, j := 0, 0; i < l; i++ {
		if j == keySize {
			j = 0
		}
		result[j] ^= key[i]
		j++
	}

	return
}

// Encrypted values have the "$<version>$<nonce>$<ciphertext>" format, where the nonce and the ciphertext
// are base64 encoded. Values without the "$" prefix are encrypted with the deprecated v0 scheme
// (AES-CFB8 with a static IV). The base64 alphabet doesn't contain "$", so the formats can't be confused.
const (
	versionSeparator = "$"
	// encryptionV1 is AES-256-GCM with a random 96-bit nonce per value and the key derived with HKDF-SHA256.
	encryptionV1 = "01"
)

// Encrypt encrypts the data with the latest encryption scheme.
func Encrypt(data string) string {
	if data == "" {
		return ""
	}
	aead, err := gcm()
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	ciphertext := aead.Seal(nil, nonce, []byte(data), nil)

	return versionSeparator + encryptionV1 + versionSeparator +
		base64.StdEncoding.EncodeToString(nonce) + versionSeparator +
		base64.StdEncoding.EncodeToString(ciphertext)
}

// Decrypt decrypts the data encrypted with any of the supported encryption schemes.
func Decrypt(data string) string {
	if data == "" {
		return ""
	}
	var (
		res string
		err error
	)
	if strings.HasPrefix(data, versionSeparator) {
		res, err = decrypt(data)
	} else {
		res, err = v0Decrypt(data)
	}
	if err != nil {
		panic(err)
	}

	return res
}

// gcm returns the AES-256-GCM cipher of the v1 encryption scheme.
func gcm() (cipher.AEAD, error) {
	key, err := createKey(Cryptokey, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

// decrypt decrypts the data in the "$<version>$<nonce>$<ciphertext>" format.
func decrypt(data string) (string, error) {
	parts := strings.Split(data, versionSeparator)
	if len(parts) != 4 || parts[0] != "" {
		return "", fmt.Errorf("malformed encrypted value")
	}
	if parts[1] != encryptionV1 {
		return "", fmt.Errorf("unsupported encryption version %q", parts[1])
	}
	nonce, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("malformed nonce: %v", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return "", fmt.Errorf("malformed ciphertext: %v", err)
	}
	aead, err := gcm()
	if err != nil {
		return "", err
	}
	if len(nonce) != aead.NonceSize() {
		return "", fmt.Errorf("invalid nonce size %d", len(nonce))
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("unable to decrypt: %v", err)
	}

	return string(plaintext), nil
}

// v0Decrypt decrypts the data encrypted with the v0 scheme: AES-CFB8 with a static IV, without a version prefix.
//
// Deprecated: v0 is only used to read records saved before the versioned encryption was introduced.
func v0Decrypt(data string) (string, error) {
	key := v0CreateKey(Cryptokey, 32)
	iv := Cryptokey[len(Cryptokey)-aes.BlockSize:]
	ciphertext, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	stream := v0CFB8Decrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

// GetOrgs gets a list of all installed organizations with their credentials
func GetOrgs() []OrganizationCredentials {
	var list []OrganizationCredentials
	iter := DB.NewIterator(nil, nil)
	for ok := iter.Seek([]byte(TeamPrefix + ":")); ok; ok = iter.Next() {
		key := iter.Key()
		if string(key) >= TeamPrefix+"~" {
			break
		}
		slackTeamID := string(key)[len(TeamPrefix)+1:]
		var credentials OrganizationCredentials
		if err := json.Unmarshal([]byte(Decrypt(string(iter.Value()))), &credentials); err != nil {
			log.Fatalf("Could not decode a JSON while retrieving an organization credentials: %v", err)
		}

		credentials.SlackTeamID = slackTeamID
		slackToken, ok := GetSlackUserToken(slackTeamID, credentials.SlackAdminUserID)
		if !ok {
			continue
		}
		credentials.SlackToken = slackToken
		list = append(list, credentials)
	}
	iter.Release()

	return list
}

// GetOrg gets an organization credentials for the specific Slack team
func GetOrg(slackTeamID string) (OrganizationCredentials, bool) {
	res := OrganizationCredentials{}
	data, err := DB.Get([]byte(TeamPrefix+":"+slackTeamID), nil)

	if err != nil {
		log.Errorf("Could not retrieve an organization from the database: %v", err)

		return res, false
	}

	if len(data) == 0 {
		return res, false
	}

	if err := json.Unmarshal([]byte(Decrypt(string(data))), &res); err != nil {
		log.Errorf("Could not decode a JSON while retrieving an organization: %v", err)

		return res, false
	}

	return res, true
}

// PutOrg saves an organization credentials
func PutOrg(org *OrganizationCredentials) error {
	data, err := json.Marshal(org)
	if err != nil {
		return err
	}
	err = DB.Put([]byte(TeamPrefix+":"+org.SlackTeamID), []byte(Encrypt(string(data))), nil)

	return err
}

// GetSlackUserToken gets an auth token of the Slack user for the specific workspace.
func GetSlackUserToken(slackTeamID string, slackUserID string) (SlackToken, bool) {
	token := SlackToken{}
	data, err := DB.Get([]byte(UserPrefix+":"+slackUserID+":"+slackTeamID), nil)
	if err != nil {
		return token, false
	}

	if err := json.Unmarshal([]byte(Decrypt(string(data))), &token); err != nil {
		log.Fatalf("Could not decode a JSON while retrieving a user token: %v", err)
	}

	return token, true
}

// PutSlackUserToken saves an auth token of the Slack user for the specific workspace.
func PutSlackUserToken(slackTeamID string, slackUserID string, token SlackToken) error {
	b, err := json.Marshal(token)
	if err != nil {
		log.Errorf("Could not encode to a JSON string while saving a user token: %v", err)

		return err
	}
	err = DB.Put([]byte(UserPrefix+":"+slackUserID+":"+slackTeamID), []byte(Encrypt(string(b))), nil)

	return err
}

// GetWIOMessage gets the "who is out" message for the specific Slack workspace,
// which is cached in the database and gets refreshed by the poller.
func GetWIOMessage(slackTeamID string) ([]WhoIsOutMessage, error) {
	res := make([]WhoIsOutMessage, 0)
	data, err := DB.Get([]byte(WhoIsOutPrefix+":"+slackTeamID), nil)
	if err != nil {
		return res, err
	}
	if err := json.Unmarshal([]byte(Decrypt(string(data))), &res); err != nil {
		log.Errorf("Could not decode a JSON while retrieving a who-is-out message: %v", err)

		return res, err
	}

	return res, nil
}

// PutWIOMessage refreshes the "who is out" message for the specific Slack workspace.
func PutWIOMessage(slackTeamID string, message []WhoIsOutMessage) error {
	jsonStr, err := json.Marshal(message)
	if err != nil {
		log.Errorf("Could not encode to a JSON string while saving a who-is-out message: %v", err)

		return err
	}

	err = DB.Put([]byte(WhoIsOutPrefix+":"+slackTeamID), []byte(Encrypt(string(jsonStr))), nil)

	return err
}

// PutOrgDepartments put a list of available departments to the cache
func PutOrgDepartments(slackTeamID string, data DepartmentCache) error {
	jsonStr, err := json.Marshal(data)
	if err != nil {
		log.Errorf("Could not encode to a JSON string while saving departments: %v", err)

		return err
	}

	err = DB.Put([]byte(DepartmentsPrefix+":"+slackTeamID), []byte(Encrypt(string(jsonStr))), nil)

	return err
}

// GetOrgDepartments gets a list of departments from the cache
func GetOrgDepartments(slackTeamID string) (*DepartmentCache, bool) {
	res := &DepartmentCache{}
	data, err := DB.Get([]byte(DepartmentsPrefix+":"+slackTeamID), nil)
	if err != nil {
		log.Errorf("Could not read a list of departments from the database: %v", err)

		return nil, false
	}
	if len(data) == 0 {
		return res, false
	}
	if err := json.Unmarshal([]byte(Decrypt(string(data))), res); err != nil {
		log.Errorf("Could not decode a JSON while retrieving departments: %v", err)

		return nil, false
	}

	return res, true
}

// PutInstallCallback saves an installation callback meta information to process with the further callback.
// The callback expires in InstallCallbackTTL.
func PutInstallCallback(state string, data InstallCallback) error {
	data.ExpiresAt = time.Now().Add(InstallCallbackTTL).Unix()
	jsonString, err := json.Marshal(data)
	if err != nil {
		log.Errorf("Could not encode to a JSON string while saving an install callback: %v", err)

		return err
	}
	err = DB.Put([]byte(CallbackPrefix+":"+state), []byte(Encrypt(string(jsonString))), nil)

	return err
}

// decodeInstallCallback decrypts and decodes a stored install callback.
func decodeInstallCallback(data []byte) (result *InstallCallback, err error) {
	defer func() {
		// Decrypt panics on a corrupted record.
		if r := recover(); r != nil {
			result, err = nil, fmt.Errorf("unable to decrypt: %v", r)
		}
	}()
	result = &InstallCallback{}
	if err = json.Unmarshal([]byte(Decrypt(string(data))), result); err != nil {
		return nil, err
	}

	return result, nil
}

// expired tells whether the callback can't be used anymore.
// Callbacks saved before the expiration was introduced don't have it and are considered expired.
func (cb *InstallCallback) expired(now time.Time) bool {
	return cb.ExpiresAt <= now.Unix()
}

// GetInstallCallback gets an installation callback meta information.
// An expired callback is removed and ErrInstallCallbackExpired is returned.
func GetInstallCallback(state string) (*InstallCallback, error) {
	b, err := DB.Get([]byte(CallbackPrefix+":"+state), nil)
	if err != nil {
		return nil, err
	}
	result, err := decodeInstallCallback(b)
	if err != nil {
		log.Errorf("Could not decode a JSON while reading an install callback: %v", err)

		return nil, err
	}
	if result.expired(time.Now()) {
		if err := DeleteInstallCallback(state); err != nil {
			log.Errorf("Could not remove an expired install callback: %v", err)
		}

		return nil, ErrInstallCallbackExpired
	}

	return result, nil
}

// PurgeExpiredInstallCallbacks removes install callbacks that have expired by the specified time,
// as well as the ones that can't be decoded. It returns the number of removed callbacks.
func PurgeExpiredInstallCallbacks(now time.Time) (int, error) {
	iter := DB.NewIterator(util.BytesPrefix([]byte(CallbackPrefix+":")), nil)
	defer iter.Release()
	batch := new(leveldb.Batch)
	for iter.Next() {
		cb, err := decodeInstallCallback(iter.Value())
		if err != nil || cb.expired(now) {
			batch.Delete(append([]byte(nil), iter.Key()...))
		}
	}
	if err := iter.Error(); err != nil {
		return 0, err
	}
	if batch.Len() == 0 {
		return 0, nil
	}

	return batch.Len(), DB.Write(batch, nil)
}

// DeleteInstallCallback removes an installation callback meta information.
func DeleteInstallCallback(triggerID string) (err error) {
	err = DB.Delete([]byte(CallbackPrefix+":"+triggerID), nil)

	return
}

// GetAppliedStatuses returns statuses set by the bot in the specific Slack workspace, keyed by the Slack user ID.
func GetAppliedStatuses(slackTeamID string) map[string]AppliedStatus {
	res := make(map[string]AppliedStatus)
	prefix := StatusPrefix + ":" + slackTeamID + ":"
	iter := DB.NewIterator(util.BytesPrefix([]byte(prefix)), nil)
	defer iter.Release()
	for iter.Next() {
		userID := string(iter.Key())[len(prefix):]
		var s AppliedStatus
		if err := json.Unmarshal([]byte(Decrypt(string(iter.Value()))), &s); err != nil {
			log.Errorf("Could not decode a JSON while retrieving an applied status: %v", err)

			continue
		}
		res[userID] = s
	}

	return res
}

// PutAppliedStatus saves the status that has been set by the bot for the specific user.
func PutAppliedStatus(slackTeamID string, slackUserID string, s AppliedStatus) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}

	return DB.Put([]byte(StatusPrefix+":"+slackTeamID+":"+slackUserID), []byte(Encrypt(string(b))), nil)
}

// DeleteAppliedStatus forgets the status that has been set by the bot for the specific user.
func DeleteAppliedStatus(slackTeamID string, slackUserID string) error {
	return DB.Delete([]byte(StatusPrefix+":"+slackTeamID+":"+slackUserID), nil)
}
