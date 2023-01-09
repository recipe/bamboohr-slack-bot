package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gookit/config"
	"github.com/recipe/bamboohr-slack-bot/internal/bamboohr"
	"github.com/recipe/bamboohr-slack-bot/internal/database"
	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CommandHandler handles the /whoisout Slack command requests
func CommandHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return
	}

	slackSigningSecret, ok := config.String("slack_signing_secret")
	if !ok {
		log.Error("The slack_signing_secret must be set in the config.yml.")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}

	// Validate the request
	sig := r.Header.Get("X-Slack-Signature")
	if sig == "" {
		http.Error(w, "The X-Slack-Signature header is missing.", http.StatusBadRequest)

		return
	}
	ts := r.Header.Get("X-Slack-Request-Timestamp")
	if ts == "" {
		http.Error(w, "The X-Slack-Request-Timestamp header is missing.", http.StatusBadRequest)

		return
	}
	its, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		http.Error(w, "Invalid X-Slack-Request-Timestamp value.", http.StatusBadRequest)

		return
	}
	tts := time.Unix(its, 0)
	clockSkew := math.Abs(float64(time.Now().Unix() - tts.Unix()))
	if clockSkew > 1000 {
		http.Error(w, fmt.Sprintf("Clock skew: %d sec.", int(clockSkew)), http.StatusForbidden)

		return
	}

	payload, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("Error reading the body while handling the POST %s request: %v", r.URL.Path, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}

	log.Debugf("Handling the POST %s request. Payload: %s", r.URL.Path, payload)

	h := hmac.New(sha256.New, []byte(slackSigningSecret))
	h.Write([]byte("v0:" + ts + ":"))
	h.Write(payload)
	sha := hex.EncodeToString(h.Sum(nil))
	if "v0="+sha != sig {
		log.Debugf("Signature does not match. Check the slack_signing_secret in the config.yml.")
		http.Error(w, "Signature does not match (%s).", http.StatusForbidden)

		return
	}

	q, err := url.ParseQuery(string(payload))
	if err != nil {
		log.Debugf("Unable to parse the payload: %v", err)
		http.Error(w, "Malformed payload", http.StatusBadRequest)

		return
	}
	teamID := q.Get("team_id")
	userID := q.Get("user_id")
	triggerID := q.Get("trigger_id")
	responseURL := q.Get("response_url")
	text := q.Get("text")
	if teamID == "" || userID == "" || triggerID == "" || responseURL == "" {
		http.Error(w, "Invalid request.", http.StatusBadRequest)

		return
	}

	var departmentList map[int]string
	department := ""

	// At this point the request is considered to be valid.
	if text != "" {
		tokens := strings.Fields(text)
		if tokens[0] == "install" {
			log.Debugf("Starting the install command.")
			ok := len(tokens) == 3
			if ok {
				ok, _ = regexp.MatchString("^(?i)[a-z][a-z0-9_]+$", tokens[1])
			}
			if ok {
				ok, _ = regexp.MatchString("^(?i)[a-f0-9]{40,}$", tokens[2])
			}
			if !ok {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = fmt.Fprintln(w, CommandUsage)

				return
			}

			// All further responses should go through response URL
			w.WriteHeader(http.StatusOK)

			cb := database.InstallCallback{
				ResponseURL:    responseURL,
				BambooHROrg:    tokens[1],
				BambooHRSecret: tokens[2],
			}
			ProcessInstallCommand(cb, triggerID, teamID, userID, true)

			return
		} else if tokens[0] == "in" && len(tokens) > 1 {
			department = strings.Join(tokens[1:], " ")

			departmentList, ok = GetDepartmentsList(teamID)
			if ok {
				// validating the input
				valid := false
				actualList := make([]string, 0)
				for _, d := range departmentList {
					actualList = append(actualList, d)
					if strings.EqualFold(d, department) {
						valid = true
					}
				}
				if !valid {
					w.Header().Set("Content-Type", "text/plain")
					_, _ = fmt.Fprintln(w, "Hey, here is the list of available departments: `"+
						strings.Join(actualList, "`, `")+"`.")

					return
				}
			}
		} else {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprintln(w, CommandUsage)

			return
		}
	}

	log.Debugf("Responding to the POST %s command.", r.URL.Path)
	message := make([]string, 0)
	wioMessage, err := database.GetWIOMessage(teamID)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}
	if len(wioMessage) > 0 {
		for _, m := range wioMessage {
			if department != "" {
				if m.Employee.Info == nil || !strings.EqualFold(m.Employee.Info.Department, department) {
					continue
				}
			}
			dateHumanReadable, _ := FormatDate(m.TimeOff.End, "Monday, 02 Jan")
			message = append(message, fmt.Sprintf(
				"<@%s> (%s) %s %s to %s",
				m.Employee.SlackUser.ID,
				m.Employee.SlackUser.RealName,
				m.TimeOff.Type.Text,
				m.TimeOff.Type.Icon,
				dateHumanReadable,
			))
		}
	}

	if len(message) == 0 {
		message = append(message, "Nothing found.")
	}

	w.Header().Set("Content-Type", "application/json")

	jsonMessage, err := json.Marshal(map[string]string{"text": strings.Join(message, "\n")})
	if err != nil {
		log.Errorf("Could not encode to a JSON string: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}
	_, _ = fmt.Fprintln(w, string(jsonMessage))
}

// GetDepartmentsList gets a cached list of departments for a specific Slack team
func GetDepartmentsList(slackTeamID string) (map[int]string, bool) {
	result := make(map[int]string)
	deps, ok := database.GetOrgDepartments(slackTeamID)
	if !ok || deps.ExpiresAt < time.Now().Unix() {
		// The list does not exist, or it is expired.
		// Requesting the list of departments.
		org, ok := database.GetOrg(slackTeamID)
		if !ok {
			return result, false
		}
		bAPI := bamboohr.New(org.BambooHROrg, org.BambooHRSecret)
		depsList, err := bAPI.GetDepartments()
		if err != nil {
			log.Errorf("Unable to get a list of departments: %v", err)

			return result, false
		}
		// Hits the cache
		_ = database.PutOrgDepartments(slackTeamID, database.DepartmentCache{
			Departments: depsList,
			ExpiresAt:   time.Now().Unix() + 3600, // 1 hour
		})

		return depsList, true
	}

	return deps.Departments, true
}

// RedirectHandler OAuth redirect handler is used when a user allows application permissions.
func RedirectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return
	}

	log.WithFields(log.Fields{"RequestURI": r.RequestURI}).Debug("Redirect request.")

	slackClientSecret, ok := config.String("slack_client_secret")
	if !ok {
		log.Error("The slack_client_secret must be provided in the config.yml.")
		http.Redirect(w, r, "/?error=internal_server_error", http.StatusSeeOther)

		return
	}
	slackClientID, ok := config.String("slack_client_id")
	if !ok {
		log.Error("The slack_client_id must be provided in the config.yml.")
		http.Redirect(w, r, "/?error=internal_server_error", http.StatusSeeOther)

		return
	}

	_ = r.ParseForm()
	code := strings.TrimSpace(r.Form.Get("code"))
	qError := r.Form.Get("error")
	state := strings.TrimSpace(r.Form.Get("state"))

	if qError != "" {
		if state != "" {
			// Trying to delete previously saved callback if it exists.
			_ = database.DeleteInstallCallback(state)
		}
		// User has chosen not to proceed with the authorization.
		// Redirecting to the main page.
		http.Redirect(w, r, "/?error=user_denial", http.StatusSeeOther)

		return
	} else if code == "" {
		http.Error(w, "Invalid request.", http.StatusBadRequest)

		return
	}

	log.Debug("Redirect request: requesting an OAuth token.")

	httpclient := &http.Client{Timeout: 10 * time.Second}
	token, err := slack.GetOAuthResponse(httpclient, slackClientID, slackClientSecret, code, "")
	if err != nil || !token.Ok {
		log.Errorf("Could not get an OAuth token: %v", err)
		http.Redirect(w, r, "/?error=oauth_error", http.StatusSeeOther)

		return
	}
	if token.UserID == "" {
		log.Error("Unexpected GET OAuth response: the UserID is missing.")
		http.Redirect(w, r, "/?error=no_user_id", http.StatusSeeOther)

		return
	}
	if err = database.PutSlackUserToken(token.TeamID, token.UserID, database.SlackToken(*token)); err != nil {
		log.Errorf("Could not save the token to the dadabase: %v", err)
		http.Redirect(w, r, "/?error=db_error", http.StatusSeeOther)

		return
	}

	log.WithFields(log.Fields{
		"UserID":   token.UserID,
		"TeamName": token.TeamName,
		"TeamID":   token.TeamID,
	}).Info("Slack token has been saved.")

	http.Redirect(w, r, "/?success=1", http.StatusSeeOther)

	if state != "" {
		go func() {
			log.Debug("Redirect request: trying to finish the installation request.")
			cb, err := database.GetInstallCallback(state)
			if err != nil {
				log.Debug("No install callback found.")

				return
			}
			ProcessInstallCommand(*cb, state, token.TeamID, token.UserID, false)

			log.Debug("Redirect request: removing the callback from the database.")
			// Remove callback as it's only considered to be a two-step workflow
			if err = database.DeleteInstallCallback(state); err != nil {
				log.Errorf("Could not remove the install callback from the database: %v", err)
			}
		}()
	}
}

// PostToResponseURL responds back to a Slack user with the message using the callback URL provided with
// the Slack command request.
func PostToResponseURL(URL string, message string) error {
	var b []byte
	var err error

	log.WithField("Message", message).Debugf("Replying back to the user.")

	httpclient := &http.Client{Timeout: 5 * time.Second}
	if len(message) > 0 && message[0:1] != "{" {
		m := make(map[string]string)
		m["text"] = message
		b, err = json.Marshal(m)
		if err != nil {
			return err
		}
	} else {
		b = []byte(message)
	}
	req, err := http.NewRequest(http.MethodPost, URL, bytes.NewBuffer(b))
	if err != nil {
		return fmt.Errorf("unable to initialize an HTTP client. %v", err)
	}
	req.Header = http.Header{
		"Content-Type": {"application/json; charset=utf-8"},
	}

	res, err := httpclient.Do(req)
	if err != nil {
		return err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode == http.StatusOK {
		return nil
	}

	log.WithFields(log.Fields{"URL": URL, "Body": string(body)}).Error("Unable to make a POST request.")

	return fmt.Errorf("unable to make a POST request to the response URL (%s)", URL)
}

// ProcessInstallCommand does an installation of a new BambooHR organization to a Slack workspace.
// It validates the request and all necessary permissions.
func ProcessInstallCommand(
	callback database.InstallCallback,
	triggerID string,
	teamID string,
	userID string,
	requestToken bool,
) {
	log.Debug("Processing the install command")

	slackClientID, ok := config.String("slack_client_id")
	if !ok {
		log.Errorf("The slack_client_id must be provided in the config.yml")

		_ = PostToResponseURL(
			callback.ResponseURL,
			fmt.Sprintf("Sorry, internal error occurred. Please try again later."),
		)

		return
	}

	reqToken := func(reason string) {
		if requestToken {
			// Store the secret to the database to proceed later right after a redirect,
			// as the Team ID and User ID should come with redirect request.
			if err := database.PutInstallCallback(triggerID, callback); err != nil {
				_ = PostToResponseURL(
					callback.ResponseURL,
					"Sorry, internal error occurred. Please try again later.",
				)

				return
			}
			log.Debug("Responding to the install command with a request for additional permissions.")
			// Respond with install button to request necessary permissions passing the triggerID as the "code"
			_ = PostToResponseURL(
				callback.ResponseURL,
				`{
    "text": "To allow application to change user's statuses it needs to request some additional permissions.",
    "attachments": [
        {
            "attachment_type": "default",
            "fallback": "Adding this command requires an official Slack client.",
            "actions": [
                {
                    "text": "Review Permissions",
                    "type": "button",
                    "url": "https://slack.com/oauth/authorize?client_id=`+url.QueryEscape(slackClientID)+
					`&state=`+url.QueryEscape(triggerID)+
					`&scope=`+SlackScope+`"
                }
            ]
        }
    ]
}`)
		} else {
			_ = PostToResponseURL(
				callback.ResponseURL,
				"Sorry, I couldn't process your request because of unexpected error. "+reason,
			)
		}
	}

	log.Debug("Install: Checking if a user token exists in the database.")
	slackToken, ok := database.GetSlackUserToken(teamID, userID)
	if !ok {
		reqToken("Slack token does not exist in the database.")

		return
	}

	log.Debug("Install: Checking Slack token scopes by requesting api.test endpoint.")
	// Using the token to check whether the user is privileged
	sActualScope, err := SlackGetScopes(slackToken.AccessToken)
	if err != nil {
		reqToken(fmt.Sprintf("A Slack API request caused error: %v", err))

		return
	}
	missing := make([]string, 0)
	actualScope := make(map[string]bool)
	for _, v := range strings.Split(sActualScope, ",") {
		actualScope[v] = true
	}
	for _, v := range strings.Split(SlackScope, ",") {
		_, ok := actualScope[v]
		if !ok {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		reqToken(fmt.Sprintf("The following scopes are missing: %s.", strings.Join(missing, ",")))

		return
	}

	log.Debug("Install: Trying to request the user.info endpoint to check if the user is privileged.")
	sAPI := slack.New(slackToken.AccessToken)
	user, err := sAPI.GetUserInfo(userID)
	if err != nil {
		reqToken(fmt.Sprintf("A Slack API request caused error: %s", err.Error()))

		return
	}

	if !user.IsAdmin && !user.IsOwner && !user.IsPrimaryOwner {
		_ = PostToResponseURL(callback.ResponseURL, "Sorry you're not workspace admin in Slack.")

		return
	}

	log.Debugf(
		"Install: Trying to fetch users list from BambooHR (%s) validating API secret.",
		callback.BambooHROrg,
	)

	bAPI := bamboohr.New(callback.BambooHROrg, callback.BambooHRSecret)
	_, err = bAPI.GetEmployeeList()
	if err != nil {
		_ = PostToResponseURL(
			callback.ResponseURL,
			fmt.Sprintf(
				"Could not retrieve a list of employees from BambooHR "+
					"with the provided organization name and token: %s",
				err.Error(),
			))

		return
	}

	log.Debug("Install: Finishing an installation by storing the credentials to the database.")

	org := database.OrganizationCredentials{
		BambooHROrg:      callback.BambooHROrg,
		BambooHRSecret:   callback.BambooHRSecret,
		SlackTeamID:      teamID,
		SlackAdminUserID: userID,
	}
	err = database.PutOrg(&org)
	if err != nil {
		_ = PostToResponseURL(
			callback.ResponseURL,
			"Could not save the credentials due to an internal server error. Please try again later.",
		)

		return
	}

	log.Debug("Install: Responding with a successful message to Slack.")

	_ = PostToResponseURL(
		callback.ResponseURL,
		"Congratulations! Now your team profile statuses will be synchronizing with BambooHR.",
	)
}

// SlackGetScopes requests the scopes for the specific Slack token.
func SlackGetScopes(token string) (string, error) {
	type tResponse struct {
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}
	b := bytes.NewBufferString("")
	req, err := http.NewRequest(http.MethodPost, "https://slack.com/api/api.test", b)
	if err != nil {
		return "", fmt.Errorf("unable to initialize an HTTP client. %v", err)
	}
	req.Header = http.Header{
		"Authorization":  {"Bearer " + token},
		"Content-Type":   {"application/json; charset=utf-8"},
		"Accept-Charset": {"utf-8"},
	}
	client := &http.Client{Timeout: 5 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	s := tResponse{}
	err = json.NewDecoder(res.Body).Decode(&s)
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error while requesting the api.test")
	}
	if !s.OK {
		return "", fmt.Errorf("error while requesting the api.test Slack endpoint: %s", s.Error)
	}

	return res.Header.Get("X-OAuth-Scopes"), nil
}
