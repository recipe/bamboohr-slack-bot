package database

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"github.com/syndtr/goleveldb/leveldb"
	"golang.org/x/sys/unix"
)

const (
	TeamPrefix     = "TEAM"
	UserPrefix     = "USER"
	WhoIsOutPrefix = "WIO"
	CallbackPrefix = "CALLBACK"
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
	ResponseURL    string `json:"response_url"`
	BambooHROrg    string `json:"bamboohr_org"`
	BambooHRSecret string `json:"bamboohr_secret"`
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

func newCFB8Encrypter(block cipher.Block, iv []byte) cipher.Stream {
	return newCFB8(block, iv, false)
}

func newCFB8Decrypter(block cipher.Block, iv []byte) cipher.Stream {
	return newCFB8(block, iv, true)
}

func newCFB8(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
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

func createKey(key []byte, keySize int) (result []byte) {
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

func Encrypt(data string) string {
	if data == "" {
		return ""
	}
	key := createKey(Cryptokey, 32)
	iv := Cryptokey[len(Cryptokey)-aes.BlockSize:]
	plaintext := []byte(data)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, len(plaintext))

	stream := newCFB8Encrypter(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	return encoded
}

func Decrypt(data string) string {
	if data == "" {
		return ""
	}
	key := createKey(Cryptokey, 32)
	iv := Cryptokey[len(Cryptokey)-aes.BlockSize:]
	ciphertext, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	stream := newCFB8Decrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	decoded := fmt.Sprintf("%s", ciphertext)

	return decoded
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
		slackTeamId := string(key)[len(TeamPrefix)+1:]
		var credentials OrganizationCredentials
		if err := json.Unmarshal([]byte(Decrypt(string(iter.Value()))), &credentials); err != nil {
			log.Fatalf("Could not decode a JSON while retrieving an organization credentials: %v", err)
		}

		credentials.SlackTeamID = slackTeamId
		slackToken, ok := GetSlackUserToken(slackTeamId, credentials.SlackAdminUserID)
		if !ok {
			continue
		}
		credentials.SlackToken = slackToken
		list = append(list, credentials)
	}
	iter.Release()

	return list
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
func GetWIOMessage(slackTeamID string) string {
	data, err := DB.Get([]byte(WhoIsOutPrefix+":"+slackTeamID), nil)
	if err != nil {
		return ""
	}

	return Decrypt(string(data))
}

// PutWIOMessage refreshes the "who is out" message for the specific Slack workspace.
func PutWIOMessage(slackTeamID string, message string) (err error) {
	err = DB.Put([]byte(WhoIsOutPrefix+":"+slackTeamID), []byte(Encrypt(message)), nil)

	return
}

// PutInstallCallback saves an installation callback meta information to process with the further callback.
func PutInstallCallback(triggerID string, data InstallCallback) error {
	jsonString, err := json.Marshal(data)
	if err != nil {
		log.Errorf("Could not encode to a JSON string while saving an install callback: %v", err)

		return err
	}
	err = DB.Put([]byte(CallbackPrefix+":"+triggerID), []byte(Encrypt(string(jsonString))), nil)

	return err
}

// GetInstallCallback gets an installation callback meta information.
func GetInstallCallback(triggerID string) (*InstallCallback, error) {
	b, err := DB.Get([]byte(CallbackPrefix+":"+triggerID), nil)
	if err != nil {
		return nil, err
	}
	result := &InstallCallback{}
	if err = json.Unmarshal(b, result); err != nil {
		log.Errorf("Could not dencode to a JSON while reading an install callback: %v", err)

		return nil, err
	}

	return result, nil
}

// DeleteInstallCallback removes an installation callback meta information.
func DeleteInstallCallback(triggerID string) (err error) {
	err = DB.Delete([]byte(CallbackPrefix+":"+triggerID), nil)

	return
}
