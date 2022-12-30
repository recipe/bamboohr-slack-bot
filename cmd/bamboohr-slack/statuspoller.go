package main

import (
	"errors"
	"fmt"
	"github.com/gookit/config"
	"github.com/recipe/bamboohr-slack-bot/internal/bamboohr"
	"github.com/recipe/bamboohr-slack-bot/internal/database"
	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"strings"
	"time"
)

// TimeOffType struct is used as the config definition
type TimeOffType struct {
	OrderNumber  int
	BambooHRType string
	Text         string
	Icon         string
}

// TimeOffTypeList is the list of the known time-off types that are defined in the config.yml
type TimeOffTypeList map[string]TimeOffType

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

	var timeOffTypeList TimeOffTypeList
	timeOffTypeList = make(TimeOffTypeList)
	for n, value := range configTimeOffTypes.([]interface{}) {
		if len(value.([]interface{})) < 3 {
			return nil, fmt.Errorf("invalid time off type configuration at position %d", n)
		}
		timeOffType := TimeOffType{
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

// Run polls all installed organizations and calculates who is out today.
func Run() error {
	unknownTimeOffTypeIcon, ok := config.String("unknown_type_icon")
	if !ok {
		return fmt.Errorf("the key unknown_type_icon isn't set in the config.yml")
	}

	timeOffTypeList, err := loadTypes()
	if err != nil {
		return err
	}

	// For all installed organizations
	for _, org := range database.GetOrgs() {
		log.Infof("Who is out today in %s?", org.BambooHROrg)
		bAPI := bamboohr.New(org.BambooHROrg, org.BambooHRSecret)
		// Get all employees from the BambooHR
		empList, err := bAPI.GetEmployeeList()
		if err != nil {
			return fmt.Errorf("unable to get a list of employees: %v", err)
		}
		sAPI := slack.New(org.SlackToken.AccessToken)
		// Get all users for the associated Slack workspace
		list, err := sAPI.GetUsers()
		if err != nil {
			return err
		}
		// Adjust an employee with the SlackUser object to process only employees
		for _, user := range list {
			if val, ok := empList[user.Profile.Email]; ok {
				val.SlackUser = user
				empList[user.Profile.Email] = val
			}
		}
		// Current UTC time
		ts := time.Now().UTC()
		// Users can be in different time zones, therefore we have to request time-offs
		// for a period of 3 days window
		startDate := ts.Add(-time.Second * 90000).Format("2006-01-02")
		endDate := ts.Add(time.Second * 90000).Format("2006-01-02")
		// Request employee time-offs from BambooHR
		timeOffList, err := bAPI.TimeOffList(startDate, endDate)
		if err != nil {
			return err
		}
		// Transforming the list to the following structure:
		// [ EmployeeID => [ Date => TimeOffType ] ]
		var toList map[int]map[string]TimeOffType
		toList = make(map[int]map[string]TimeOffType)
		for _, timeOff := range timeOffList {
			for date := range timeOff.Dates {
				if startDate <= date && date <= endDate {
					if _, ok := toList[timeOff.EmployeeID]; !ok {
						toList[timeOff.EmployeeID] = make(map[string]TimeOffType)
					}
					t, ok := timeOffTypeList[timeOff.Type.Name]
					if !ok {
						t = TimeOffType{
							OrderNumber:  255, // Undefined time-off type has the lowest priority
							BambooHRType: timeOff.Type.Name,
							Text:         timeOff.Type.Name,
							Icon:         unknownTimeOffTypeIcon,
						}
					}
					if toList[timeOff.EmployeeID][date].BambooHRType == "" ||
						toList[timeOff.EmployeeID][date].OrderNumber > t.OrderNumber {
						// If there are two different time-offs for the same day,
						// it will select one listed first in the config.yml
						toList[timeOff.EmployeeID][date] = t
					}
				}
			}
		}

		whoIsOutMessage := make([]string, 0)

		for _, emp := range empList {
			// An employee hasn't been added to Slack yet.
			if emp.SlackUser.ID == "" {
				continue
			}
			// Is there any time off for the user?
			to, ok := toList[emp.EmployeeID]
			if !ok {
				continue
			}
			// The date in the user's time zone
			userDate := ts.Add(time.Second * time.Duration(emp.SlackUser.TZOffset)).Format("2006-01-02")
			// A time off date matches today's date for the user in his/her time zone?
			timeOffToApply, ok := to[userDate]
			if !ok {
				continue
			}
			// Set a user profile status until the midnight in user's time zone
			expectedStatusExpiration, err := Strtotime(userDate + " 23:59:59")
			if err != nil {
				return fmt.Errorf("unable to convert the date (%s) to the unix timestamp: %s", userDate, err)
			}
			expectedStatusExpiration = expectedStatusExpiration - int64(emp.SlackUser.TZOffset)

			// Produce a who is out message for the /whoisout Slack command for caching purposes.
			whoIsOutMessage = append(whoIsOutMessage, fmt.Sprintf("<@%s> (%s) %s %s",
				emp.SlackUser.ID,
				emp.SlackUser.RealName,
				timeOffToApply.Text,
				timeOffToApply.Icon,
			))

			if emp.SlackUser.Profile.StatusEmoji == timeOffToApply.Icon &&
				int64(emp.SlackUser.Profile.StatusExpiration) == expectedStatusExpiration {
				log.WithFields(log.Fields{
					"SlackID":    emp.SlackUser.ID,
					"EmployeeID": emp.EmployeeID,
					"TZOffset":   emp.SlackUser.TZOffset,
					"Emoji":      emp.SlackUser.Profile.StatusEmoji,
					"Date":       userDate,
					"Exp":        expectedStatusExpiration,
				}).Infof("Skipping. %s has actual status.", emp.SlackUser.RealName)

				continue
			}

			log.WithFields(log.Fields{
				"Status":     timeOffToApply.Text,
				"SlackID":    emp.SlackUser.ID,
				"EmployeeID": emp.EmployeeID,
				"TZOffset":   emp.SlackUser.TZOffset,
				"Emoji":      timeOffToApply.Icon,
				"Date":       userDate,
				"Exp":        expectedStatusExpiration,
				"PrevStatus": emp.SlackUser.Profile.StatusText,
				"PrevEmoji":  emp.SlackUser.Profile.StatusEmoji,
				"PrevExp":    emp.SlackUser.Profile.StatusExpiration,
			}).Infof("Setting the '%s' status for %s.", timeOffToApply.Text, emp.SlackUser.RealName)

			if (emp.SlackUser.IsAdmin || emp.SlackUser.IsOwner) && emp.SlackUser.ID != org.SlackAdminUserID {
				//If a user is the admin we have to try to use his own token, if it exists, to avoid permission errors.
				adminToken, ok := database.GetSlackUserToken(org.SlackTeamID, emp.SlackUser.ID)
				if ok {
					sAdminAPI := slack.New(adminToken.AccessToken)
					_ = sAdminAPI.SetUserCustomStatusWithUser(
						emp.SlackUser.ID,
						timeOffToApply.Text,
						timeOffToApply.Icon,
						expectedStatusExpiration,
					)
				}
			} else {
				_ = sAPI.SetUserCustomStatusWithUser(
					emp.SlackUser.ID,
					timeOffToApply.Text,
					timeOffToApply.Icon,
					expectedStatusExpiration,
				)
			}
		}

		if len(whoIsOutMessage) == 0 {
			whoIsOutMessage = append(whoIsOutMessage, "Everybody is on board.")
			log.Info("No time-offs found.")
		}

		if err := database.PutWIOMessage(org.SlackTeamID, strings.Join(whoIsOutMessage, "\n")); err != nil {
			log.Errorf("Unable to store who-is-out information to the database. %v", err)
		}
	}

	return nil
}
