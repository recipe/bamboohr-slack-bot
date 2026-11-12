package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/gookit/config"
	"github.com/recipe/bamboohr-slack-bot/internal/bamboohr"
	"github.com/recipe/bamboohr-slack-bot/internal/database"
	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
)

// LookaheadDays is how far ahead the poller looks for the end of consecutive time-offs.
const LookaheadDays = 60

// TimeOffTypeList is the list of the known time-off types that are defined in the config.yml
type TimeOffTypeList map[string]database.TimeOffType

// FormatDate formats the date in the "YYYY-MM-DD" form to a specified layout format
func FormatDate(date string, layout string) (string, error) {
	t, err := time.Parse("2006-01-02", date)
	if err != nil {
		return "", err
	}
	return t.Format(layout), nil
}

// Strtotime parses a formatted time string "YYYY-MM-DD HH:mm:ss" and returns the Unix timestamp.
// The string is considered to be provided in UTC time zone.
func Strtotime(str string) (int64, error) {
	layout := "2006-01-02 15:04:05"
	t, err := time.Parse(layout, str)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

// loadTypes loads the time-offs from the config.yml
func loadTypes() (TimeOffTypeList, error) {
	cnf := config.Data()
	configTimeOffTypes, ok := cnf["types"]
	if !ok {
		return nil, errors.New("the 'types' data set is not defined in the config")
	}
	timeOffTypeList := make(TimeOffTypeList)
	for n, value := range configTimeOffTypes.([]interface{}) {
		if len(value.([]interface{})) < 3 {
			return nil, fmt.Errorf("invalid time off type configuration at position %d", n)
		}
		timeOffType := database.TimeOffType{
			OrderNumber:  n,
			BambooHRType: fmt.Sprintf("%s", value.([]interface{})[0]),
			Text:         fmt.Sprintf("%s", value.([]interface{})[1]),
			Icon:         fmt.Sprintf("%s", value.([]interface{})[2]),
		}
		timeOffTypeList[timeOffType.BambooHRType] = timeOffType
	}
	if len(timeOffTypeList) == 0 {
		return nil, errors.New("the 'types' must be provided in the config.yml")
	}
	return timeOffTypeList, nil
}

// PollerSettings is the part of the config.yml used by the status poller.
type PollerSettings struct {
	Types       TimeOffTypeList
	UnknownIcon string
}

// loadPollerSettings loads the status poller settings from the config.yml.
func loadPollerSettings() (PollerSettings, error) {
	unknownIcon, ok := config.String("unknown_type_icon")
	if !ok {
		return PollerSettings{}, fmt.Errorf("the key unknown_type_icon isn't set in the config.yml")
	}
	types, err := loadTypes()
	if err != nil {
		return PollerSettings{}, err
	}
	return PollerSettings{Types: types, UnknownIcon: unknownIcon}, nil
}

// BambooHRAPI is the part of the BambooHR client used by the status poller.
type BambooHRAPI interface {
	GetEmployeeList() (map[string]bamboohr.Employee, error)
	GetEmployeeDirectory() (map[int]bamboohr.EmployeeInfo, error)
	TimeOffList(startDate string, endDate string) ([]bamboohr.TimeOff, error)
	GetHolidays(startDate string, endDate string) (map[string]bool, error)
}

// SlackAPI is the part of the Slack client used by the status poller.
type SlackAPI interface {
	GetUsers(options ...slack.GetUsersOption) ([]slack.User, error)
	SetUserCustomStatusWithUser(user, statusText, statusEmoji string, statusExpiration int64) error
}

// OrgClients are API clients of a single organization.
type OrgClients struct {
	BambooHR BambooHRAPI
	Slack    SlackAPI
	// SlackForToken creates a Slack client for the specific user token.
	SlackForToken func(token string) SlackAPI
}

// BuildTimeOffMap transforms the list of time-offs to the following structure:
// [ EmployeeID => [ Date => TimeOff ] ]. Only dates between startDate and endDate are included.
// If there are two different time-offs for the same day, the one listed first in the config.yml wins.
func BuildTimeOffMap(timeOffList []bamboohr.TimeOff, types TimeOffTypeList, unknownIcon string,
	startDate string, endDate string) map[int]map[string]database.TimeOff {
	toList := make(map[int]map[string]database.TimeOff)
	for _, timeOff := range timeOffList {
		for date := range timeOff.Dates {
			if date < startDate || date > endDate {
				continue
			}
			if _, ok := toList[timeOff.EmployeeID]; !ok {
				toList[timeOff.EmployeeID] = make(map[string]database.TimeOff)
			}
			t, ok := types[timeOff.Type.Name]
			if !ok {
				t = database.TimeOffType{
					OrderNumber:  255, // Undefined time-off type has the lowest priority
					BambooHRType: timeOff.Type.Name,
					Text:         timeOff.Type.Name,
					Icon:         unknownIcon,
				}
			}
			if cur := toList[timeOff.EmployeeID][date]; cur.Type == nil || cur.Type.OrderNumber > t.OrderNumber {
				toList[timeOff.EmployeeID][date] = database.TimeOff{
					Type:  &t,
					Start: timeOff.Start,
					End:   timeOff.End,
				}
			}
		}
	}
	return toList
}

// DayAfterTimeOff returns the first day ("YYYY-MM-DD") after the given date which is neither a time off day
// nor a company holiday. Weekends are not skipped: work schedules differ between organizations and people.
func DayAfterTimeOff(date string, limit string, timeOffs map[string]database.TimeOff,
	holidays map[string]bool) (string, error) {
	d, err := time.Parse("2006-01-02", date)
	if err != nil {
		return "", err
	}
	for {
		d = d.AddDate(0, 0, 1)
		day := d.Format("2006-01-02")
		if day > limit {
			return day, nil
		}
		if _, ok := timeOffs[day]; ok || holidays[day] {
			continue
		}
		return day, nil
	}
}

// UserDate returns today's date ("YYYY-MM-DD") in the user's time zone.
func UserDate(now time.Time, tzOffset int) string {
	return now.UTC().Add(time.Second * time.Duration(tzOffset)).Format("2006-01-02")
}

// ExpectedStatus calculates the status the user must have now. It returns false if the user isn't out today.
// The status expires at the end of the last day of the time off, in the user's time zone.
// Consecutive time-offs and company holidays right after the time off are treated as one.
func ExpectedStatus(now time.Time, tzOffset int, timeOffs map[string]database.TimeOff, holidays map[string]bool,
	limit string) (database.AppliedStatus, database.TimeOff, bool, error) {
	userDate := UserDate(now, tzOffset)
	timeOff, ok := timeOffs[userDate]
	if !ok {
		return database.AppliedStatus{}, database.TimeOff{}, false, nil
	}
	backDate, err := DayAfterTimeOff(userDate, limit, timeOffs, holidays)
	if err != nil {
		return database.AppliedStatus{}, database.TimeOff{}, false,
			fmt.Errorf("unable to calculate the end of the time off (%s): %s", userDate, err)
	}
	expiration, err := Strtotime(backDate + " 00:00:00")
	if err != nil {
		return database.AppliedStatus{}, database.TimeOff{}, false,
			fmt.Errorf("unable to convert the date (%s) to the unix timestamp: %s", backDate, err)
	}
	return database.AppliedStatus{
		Text:       timeOff.Type.Text,
		Emoji:      timeOff.Type.Icon,
		Expiration: expiration - int64(tzOffset) - 1,
	}, timeOff, true, nil
}

// HasStatus tells whether the user's current Slack status is exactly the given one.
func HasStatus(profile slack.UserProfile, s database.AppliedStatus) bool {
	return profile.StatusEmoji == s.Emoji &&
		profile.StatusText == s.Text &&
		int64(profile.StatusExpiration) == s.Expiration
}

// ShouldClearStatus tells whether the status that was set by the bot must be cleared for the user who isn't out today.
// It is cleared only if the user still has it. If the user has changed it, or it has expired, it is left as is.
func ShouldClearStatus(user slack.User, applied database.AppliedStatus, now time.Time) bool {
	return !user.Deleted &&
		user.Profile.StatusEmoji == applied.Emoji &&
		user.Profile.StatusText == applied.Text &&
		int64(user.Profile.StatusExpiration) > now.Unix()
}

// setStatus sets the Slack profile status for the user.
func setStatus(org database.OrganizationCredentials, clients OrgClients, user slack.User,
	s database.AppliedStatus) error {
	if (user.IsAdmin || user.IsOwner) && user.ID != org.SlackAdminUserID {
		// If a user is the admin we have to try to use his own token, if it exists, to avoid permission errors.
		adminToken, ok := database.GetSlackUserToken(org.SlackTeamID, user.ID)
		if !ok {
			return errors.New("the user is an admin who hasn't authorized the app")
		}
		return clients.SlackForToken(adminToken.AccessToken).SetUserCustomStatusWithUser(user.ID, s.Text, s.Emoji, s.Expiration)
	}
	return clients.Slack.SetUserCustomStatusWithUser(user.ID, s.Text, s.Emoji, s.Expiration)
}

// Run polls all installed organizations and calculates who is out today.
func Run() error {
	settings, err := loadPollerSettings()
	if err != nil {
		return err
	}
	slackForToken := func(token string) SlackAPI { return slack.New(token) }

	// For all installed organizations
	for _, org := range database.GetOrgs() {
		log.Infof("Who is out today in %s?", org.BambooHROrg)
		clients := OrgClients{
			BambooHR:      bamboohr.New(org.BambooHROrg, org.BambooHRSecret),
			Slack:         slack.New(org.SlackToken.AccessToken),
			SlackForToken: slackForToken,
		}
		if err := SyncOrg(org, clients, settings, time.Now()); err != nil {
			log.Errorf("Unable to sync statuses in %s: %v", org.BambooHROrg, err)
		}
	}

	return nil
}

// SyncOrg syncs Slack profile statuses of a single organization with the BambooHR time-off table.
func SyncOrg(org database.OrganizationCredentials, clients OrgClients, settings PollerSettings, now time.Time) error {
	// Get all employees from the BambooHR. The only endpoint to get email addresses
	empList, err := clients.BambooHR.GetEmployeeList()
	if err != nil {
		return fmt.Errorf("unable to get a list of employees: %v", err)
	}

	// Get all employees with links to departments, divisions and job titles
	empDirectory, err := clients.BambooHR.GetEmployeeDirectory()
	if err != nil {
		return fmt.Errorf("unable to get an employee directory: %v", err)
	}

	// Get all users for the associated Slack workspace
	list, err := clients.Slack.GetUsers()
	if err != nil {
		return fmt.Errorf("unable to get a list of Slack users: %v", err)
	}
	// Adjust an employee with the SlackUser object to process only employees
	for _, user := range list {
		if val, ok := empList[user.Profile.Email]; ok {
			val.SlackUser = user
			if dirVal, ok := empDirectory[val.EmployeeID]; ok {
				val.Info = &dirVal
			}
			empList[user.Profile.Email] = val
		}
	}
	ts := now.UTC()
	// Users can be in different time zones, therefore the window starts a day before.
	// It looks ahead to find the end of consecutive time-offs.
	startDate := ts.Add(-time.Second * 90000).Format("2006-01-02")
	endDate := ts.AddDate(0, 0, LookaheadDays).Format("2006-01-02")
	// Request employee time-offs from BambooHR
	timeOffList, err := clients.BambooHR.TimeOffList(startDate, endDate)
	if err != nil {
		return fmt.Errorf("unable to get a list of time-offs: %v", err)
	}
	// Company holidays right after a time off extend the status. They are optional.
	holidays, err := clients.BambooHR.GetHolidays(startDate, endDate)
	if err != nil {
		log.Warnf("Unable to get a list of holidays, ignoring them: %v", err)
		holidays = map[string]bool{}
	}
	toList := BuildTimeOffMap(timeOffList, settings.Types, settings.UnknownIcon, startDate, endDate)

	whoIsOutMessage := make([]database.WhoIsOutMessage, 0)
	// Statuses set by the bot during previous runs
	appliedStatuses := database.GetAppliedStatuses(org.SlackTeamID)
	// Users who are out today
	outToday := make(map[string]bool)

	for _, emp := range empList {
		// An employee hasn't been added to Slack yet.
		if emp.SlackUser.ID == "" {
			continue
		}
		// Is there any time off for the user today, in the user's time zone?
		expected, timeOffToApply, ok, err := ExpectedStatus(ts, emp.SlackUser.TZOffset, toList[emp.EmployeeID],
			holidays, endDate)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		outToday[emp.SlackUser.ID] = true

		whoIsOutMessage = append(whoIsOutMessage, database.WhoIsOutMessage{
			Employee: database.WhoIsOutMessageEmployee{
				SlackUser: database.WhoIsOutMessageSlackUser{
					ID:       emp.SlackUser.ID,
					RealName: emp.SlackUser.RealName,
				},
				Info: emp.Info,
			},
			TimeOff: timeOffToApply,
		})

		logFields := log.Fields{
			"SlackID":    emp.SlackUser.ID,
			"EmployeeID": emp.EmployeeID,
			"TZOffset":   emp.SlackUser.TZOffset,
			"Emoji":      expected.Emoji,
			"Date":       UserDate(ts, emp.SlackUser.TZOffset),
			"Exp":        expected.Expiration,
		}

		if HasStatus(emp.SlackUser.Profile, expected) {
			log.WithFields(logFields).Infof("Skipping. %s has actual status.", emp.SlackUser.RealName)
			if appliedStatuses[emp.SlackUser.ID] != expected {
				if err := database.PutAppliedStatus(org.SlackTeamID, emp.SlackUser.ID, expected); err != nil {
					log.Errorf("Unable to save the applied status: %v", err)
				}
			}

			continue
		}

		logFields["Status"] = expected.Text
		logFields["PrevStatus"] = emp.SlackUser.Profile.StatusText
		logFields["PrevEmoji"] = emp.SlackUser.Profile.StatusEmoji
		logFields["PrevExp"] = emp.SlackUser.Profile.StatusExpiration
		log.WithFields(logFields).Infof("Setting the '%s' status for %s.", expected.Text, emp.SlackUser.RealName)

		if err := setStatus(org, clients, emp.SlackUser, expected); err != nil {
			log.WithFields(logFields).Errorf("Unable to set the status for %s: %v", emp.SlackUser.RealName, err)

			continue
		}
		if err := database.PutAppliedStatus(org.SlackTeamID, emp.SlackUser.ID, expected); err != nil {
			log.Errorf("Unable to save the applied status: %v", err)
		}
	}

	// Clear statuses set by the bot for users who are not out today anymore,
	// e.g. when a time off has been withdrawn or shortened.
	slackUsers := make(map[string]slack.User, len(list))
	for _, user := range list {
		slackUsers[user.ID] = user
	}
	for userID, applied := range appliedStatuses {
		if outToday[userID] {
			continue
		}
		if user, ok := slackUsers[userID]; ok && ShouldClearStatus(user, applied, ts) {
			log.WithFields(log.Fields{
				"SlackID":    userID,
				"PrevStatus": applied.Text,
				"PrevEmoji":  applied.Emoji,
				"PrevExp":    applied.Expiration,
			}).Infof("Clearing the '%s' status for %s.", applied.Text, user.RealName)
			if err := setStatus(org, clients, user, database.AppliedStatus{}); err != nil {
				log.Errorf("Unable to clear the status for %s: %v", user.RealName, err)

				continue
			}
		}
		if err := database.DeleteAppliedStatus(org.SlackTeamID, userID); err != nil {
			log.Errorf("Unable to delete the applied status: %v", err)
		}
	}

	if err := database.PutWIOMessage(org.SlackTeamID, whoIsOutMessage); err != nil {
		log.Errorf("Unable to store who-is-out information to the database. %v", err)
	}

	return nil
}
