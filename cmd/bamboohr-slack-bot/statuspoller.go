package main

import (
	"errors"
	"fmt"
	"github.com/gookit/config"
	"github.com/recipe/bamboohr-slack-bot/internal/bamboohr"
	"github.com/recipe/bamboohr-slack-bot/internal/database"
	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"time"
)

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

		// Get all employees from the BambooHR. The only endpoint to get email addresses
		empList, err := bAPI.GetEmployeeList()
		if err != nil {
			log.Errorf("Unable to get a list of employees: %v", err)

			continue
		}

		// Get all employees with links to departments, divisions and job titles
		empDirectory, err := bAPI.GetEmployeeDirectory()
		if err != nil {
			log.Errorf("Unable to get an employee directory: %v", err)

			continue
		}

		sAPI := slack.New(org.SlackToken.AccessToken)
		// Get all users for the associated Slack workspace
		list, err := sAPI.GetUsers()
		if err != nil {
			log.Errorf("Unable to get a list of Slack users: %v", err)

			continue
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
		// Current UTC time
		ts := time.Now().UTC()
		// Users can be in different time zones, therefore we have to request time-offs
		// for a period of 3 days window
		startDate := ts.Add(-time.Second * 90000).Format("2006-01-02")
		endDate := ts.Add(time.Second * 90000).Format("2006-01-02")
		// Request employee time-offs from BambooHR
		timeOffList, err := bAPI.TimeOffList(startDate, endDate)
		if err != nil {
			log.Errorf("Unable to get a list of time-offs: %v", err)

			continue
		}
		// Transforming the list to the following structure:
		// [ EmployeeID => [ Date => TimeOffType ] ]
		var toList map[int]map[string]database.TimeOff
		toList = make(map[int]map[string]database.TimeOff)
		for _, timeOff := range timeOffList {
			for date := range timeOff.Dates {
				if startDate <= date && date <= endDate {
					if _, ok := toList[timeOff.EmployeeID]; !ok {
						toList[timeOff.EmployeeID] = make(map[string]database.TimeOff)
					}
					t, ok := timeOffTypeList[timeOff.Type.Name]
					if !ok {
						t = database.TimeOffType{
							OrderNumber:  255, // Undefined time-off type has the lowest priority
							BambooHRType: timeOff.Type.Name,
							Text:         timeOff.Type.Name,
							Icon:         unknownTimeOffTypeIcon,
						}
					}
					if toList[timeOff.EmployeeID][date].Type == nil ||
						toList[timeOff.EmployeeID][date].Type.OrderNumber > t.OrderNumber {
						// If there are two different time-offs for the same day,
						// it will select one listed first in the config.yml
						to := database.TimeOff{
							Type:  &t,
							Start: timeOff.Start,
							End:   timeOff.End,
						}
						toList[timeOff.EmployeeID][date] = to
					}
				}
			}
		}

		whoIsOutMessage := make([]database.WhoIsOutMessage, 0)

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

			if emp.SlackUser.Profile.StatusEmoji == timeOffToApply.Type.Icon &&
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
				"Status":     timeOffToApply.Type.Text,
				"SlackID":    emp.SlackUser.ID,
				"EmployeeID": emp.EmployeeID,
				"TZOffset":   emp.SlackUser.TZOffset,
				"Emoji":      timeOffToApply.Type.Icon,
				"Date":       userDate,
				"Exp":        expectedStatusExpiration,
				"PrevStatus": emp.SlackUser.Profile.StatusText,
				"PrevEmoji":  emp.SlackUser.Profile.StatusEmoji,
				"PrevExp":    emp.SlackUser.Profile.StatusExpiration,
			}).Infof("Setting the '%s' status for %s.", timeOffToApply.Type.Text, emp.SlackUser.RealName)

			if (emp.SlackUser.IsAdmin || emp.SlackUser.IsOwner) && emp.SlackUser.ID != org.SlackAdminUserID {
				//If a user is the admin we have to try to use his own token, if it exists, to avoid permission errors.
				adminToken, ok := database.GetSlackUserToken(org.SlackTeamID, emp.SlackUser.ID)
				if ok {
					sAdminAPI := slack.New(adminToken.AccessToken)
					_ = sAdminAPI.SetUserCustomStatusWithUser(
						emp.SlackUser.ID,
						timeOffToApply.Type.Text,
						timeOffToApply.Type.Icon,
						expectedStatusExpiration,
					)
				}
			} else {
				_ = sAPI.SetUserCustomStatusWithUser(
					emp.SlackUser.ID,
					timeOffToApply.Type.Text,
					timeOffToApply.Type.Icon,
					expectedStatusExpiration,
				)
			}
		}

		if err := database.PutWIOMessage(org.SlackTeamID, whoIsOutMessage); err != nil {
			log.Errorf("Unable to store who-is-out information to the database. %v", err)
		}
	}

	return nil
}
