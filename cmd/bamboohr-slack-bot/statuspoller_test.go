package main

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gookit/config"
	"github.com/gookit/config/yaml"
	"github.com/recipe/bamboohr-slack-bot/internal/bamboohr"
	"github.com/recipe/bamboohr-slack-bot/internal/database"
	"github.com/slack-go/slack"
)

// now is Friday, 2026-11-13 10:00 UTC
var now = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

func TestMain(m *testing.M) {
	database.Cryptokey = []byte(strings.Repeat("0123456789abcdef", 4))
	os.Exit(m.Run())
}

// testTypes mirrors the config.yml where the order defines the priority.
func testTypes() TimeOffTypeList {
	list := TimeOffTypeList{}
	for i, v := range [][3]string{
		{"Vacation", "On holiday", ":palm_tree:"},
		{"Sick", "Out sick", ":face_with_thermometer:"},
		{"Remote Work", "Working remotely", ":house:"},
	} {
		list[v[0]] = database.TimeOffType{OrderNumber: i, BambooHRType: v[0], Text: v[1], Icon: v[2]}
	}
	return list
}

func testSettings() PollerSettings {
	return PollerSettings{Types: testTypes(), UnknownIcon: ":grey_question:"}
}

// timeOff creates a BambooHR time off of the given type for the employee on the given dates.
func timeOff(employeeID int, typeName string, dates ...string) bamboohr.TimeOff {
	d := bamboohr.TimeOffDates{}
	for _, date := range dates {
		d[date] = json.Number("1")
	}
	return bamboohr.TimeOff{
		EmployeeID: employeeID,
		Type:       bamboohr.TimeOffType{Name: typeName},
		Start:      dates[0],
		End:        dates[len(dates)-1],
		Dates:      d,
	}
}

// expiresBefore returns the expected status expiration: the last second before the date in the time zone.
func expiresBefore(date string, tzOffset int) int64 {
	t, _ := time.Parse("2006-01-02", date)
	return t.Unix() - int64(tzOffset) - 1
}

func TestBuildTimeOffMap(t *testing.T) {
	types := testTypes()

	t.Run("overlapping time offs: the higher priority one is active regardless of the order", func(t *testing.T) {
		for _, list := range [][]bamboohr.TimeOff{
			{timeOff(1, "Sick", "2026-11-13"), timeOff(1, "Vacation", "2026-11-12", "2026-11-13")},
			{timeOff(1, "Vacation", "2026-11-12", "2026-11-13"), timeOff(1, "Sick", "2026-11-13")},
		} {
			m := BuildTimeOffMap(list, types, ":q:", "2026-11-01", "2026-11-30")
			if got := m[1]["2026-11-13"].Type.BambooHRType; got != "Vacation" {
				t.Errorf("got %s, want Vacation", got)
			}
			if got := m[1]["2026-11-12"].Type.BambooHRType; got != "Vacation" {
				t.Errorf("got %s, want Vacation", got)
			}
		}
	})

	t.Run("a lower priority time off is active on days without overlap", func(t *testing.T) {
		m := BuildTimeOffMap([]bamboohr.TimeOff{
			timeOff(1, "Vacation", "2026-11-13"),
			timeOff(1, "Remote Work", "2026-11-13", "2026-11-16"),
		}, types, ":q:", "2026-11-01", "2026-11-30")
		if got := m[1]["2026-11-13"].Type.BambooHRType; got != "Vacation" {
			t.Errorf("2026-11-13: got %s, want Vacation", got)
		}
		if got := m[1]["2026-11-16"].Type.BambooHRType; got != "Remote Work" {
			t.Errorf("2026-11-16: got %s, want Remote Work", got)
		}
	})

	t.Run("an unknown type has the lowest priority", func(t *testing.T) {
		m := BuildTimeOffMap([]bamboohr.TimeOff{
			timeOff(1, "Jury Duty", "2026-11-13", "2026-11-16"),
			timeOff(1, "Remote Work", "2026-11-13"),
		}, types, ":q:", "2026-11-01", "2026-11-30")
		if got := m[1]["2026-11-13"].Type.BambooHRType; got != "Remote Work" {
			t.Errorf("got %s, want Remote Work", got)
		}
		unknown := m[1]["2026-11-16"].Type
		if unknown.Text != "Jury Duty" || unknown.Icon != ":q:" || unknown.OrderNumber != 255 {
			t.Errorf("unexpected unknown type: %+v", unknown)
		}
	})

	t.Run("employees don't affect each other", func(t *testing.T) {
		m := BuildTimeOffMap([]bamboohr.TimeOff{
			timeOff(1, "Sick", "2026-11-13"),
			timeOff(2, "Vacation", "2026-11-13"),
		}, types, ":q:", "2026-11-01", "2026-11-30")
		if got := m[1]["2026-11-13"].Type.BambooHRType; got != "Sick" {
			t.Errorf("got %s, want Sick", got)
		}
	})

	t.Run("dates outside of the window are ignored", func(t *testing.T) {
		m := BuildTimeOffMap([]bamboohr.TimeOff{
			timeOff(1, "Vacation", "2026-10-31", "2026-11-01", "2026-11-30", "2026-12-01"),
		}, types, ":q:", "2026-11-01", "2026-11-30")
		if len(m[1]) != 2 {
			t.Errorf("got %v, want only 2026-11-01 and 2026-11-30", m[1])
		}
	})
}

func TestDayAfterTimeOff(t *testing.T) {
	days := func(dates ...string) map[string]database.TimeOff {
		m := make(map[string]database.TimeOff)
		for _, d := range dates {
			m[d] = database.TimeOff{}
		}
		return m
	}
	// 2026-11-13 is Friday
	cases := []struct {
		name     string
		date     string
		timeOffs map[string]database.TimeOff
		holidays map[string]bool
		want     string
	}{
		{"single day", "2026-11-10", days("2026-11-10"), nil, "2026-11-11"},
		{"ends on Friday: the weekend is not covered", "2026-11-12", days("2026-11-12", "2026-11-13"), nil, "2026-11-14"},
		{"the time off includes the weekend", "2026-11-13",
			days("2026-11-13", "2026-11-14", "2026-11-15", "2026-11-16"), nil, "2026-11-17"},
		{"Friday and Monday off: the weekend is a gap", "2026-11-13", days("2026-11-13", "2026-11-16"), nil, "2026-11-14"},
		{"a holiday right after the time off", "2026-11-10", days("2026-11-10"), map[string]bool{"2026-11-11": true}, "2026-11-12"},
		{"a holiday followed by another time off", "2026-11-10",
			days("2026-11-10", "2026-11-12"), map[string]bool{"2026-11-11": true}, "2026-11-13"},
		{"a holiday after the weekend", "2026-11-13", days("2026-11-13"), map[string]bool{"2026-11-16": true}, "2026-11-14"},
		{"a holiday before the time off doesn't matter", "2026-11-10", days("2026-11-10"), map[string]bool{"2026-11-09": true}, "2026-11-11"},
		{"back-to-back requests", "2026-11-10", days("2026-11-10", "2026-11-11", "2026-11-12"), nil, "2026-11-13"},
		{"a working day in between", "2026-11-10", days("2026-11-10", "2026-11-12"), nil, "2026-11-11"},
		{"longer than the lookahead", "2026-11-30", days("2026-11-30", "2026-12-01", "2026-12-02"), nil, "2026-12-02"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := DayAfterTimeOff(c.date, "2026-12-01", c.timeOffs, c.holidays)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}

	if _, err := DayAfterTimeOff("13.11.2026", "2026-12-01", nil, nil); err == nil {
		t.Error("expected an error for an invalid date")
	}
}

func TestExpectedStatus(t *testing.T) {
	timeOffs := BuildTimeOffMap([]bamboohr.TimeOff{
		timeOff(1, "Vacation", "2026-11-12", "2026-11-13"),
	}, testTypes(), ":q:", "2026-11-01", "2026-12-31")[1]

	cases := []struct {
		name     string
		tzOffset int
		out      bool
		want     int64
	}{
		{"UTC", 0, true, expiresBefore("2026-11-14", 0)},
		{"UTC+2", 7200, true, expiresBefore("2026-11-14", 7200)},
		{"UTC-8", -28800, true, expiresBefore("2026-11-14", -28800)},
		// 10:00 UTC on Friday is already Saturday in UTC+14 and the time off is over
		{"UTC+14", 50400, false, 0},
		// 10:00 UTC on Friday is 00:00 on Friday in UTC-10
		{"UTC-10", -36000, true, expiresBefore("2026-11-14", -36000)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, to, ok, err := ExpectedStatus(now, c.tzOffset, timeOffs, nil, "2026-12-31")
			if err != nil {
				t.Fatal(err)
			}
			if ok != c.out {
				t.Fatalf("out today: got %v, want %v", ok, c.out)
			}
			if !ok {
				return
			}
			if s.Expiration != c.want || s.Text != "On holiday" || s.Emoji != ":palm_tree:" {
				t.Errorf("got %+v, want expiration %d", s, c.want)
			}
			if to.Start != "2026-11-12" || to.End != "2026-11-13" {
				t.Errorf("unexpected time off: %+v", to)
			}
		})
	}

	t.Run("not out today", func(t *testing.T) {
		_, _, ok, err := ExpectedStatus(now, 0, nil, nil, "2026-12-31")
		if err != nil || ok {
			t.Errorf("got ok=%v err=%v, want not out", ok, err)
		}
	})
}

func TestHasStatus(t *testing.T) {
	s := database.AppliedStatus{Text: "On holiday", Emoji: ":palm_tree:", Expiration: 100}
	profile := slack.UserProfile{StatusText: "On holiday", StatusEmoji: ":palm_tree:", StatusExpiration: 100}
	if !HasStatus(profile, s) {
		t.Error("expected the status to match")
	}
	for name, p := range map[string]slack.UserProfile{
		"text":       {StatusText: "Lunch", StatusEmoji: ":palm_tree:", StatusExpiration: 100},
		"emoji":      {StatusText: "On holiday", StatusEmoji: ":sun:", StatusExpiration: 100},
		"expiration": {StatusText: "On holiday", StatusEmoji: ":palm_tree:", StatusExpiration: 99},
		"empty":      {},
	} {
		if HasStatus(p, s) {
			t.Errorf("%s: expected the status not to match", name)
		}
	}
}

func TestShouldClearStatus(t *testing.T) {
	applied := database.AppliedStatus{Text: "On holiday", Emoji: ":palm_tree:", Expiration: now.Unix() + 3600}
	user := func(text, emoji string, exp int64, deleted bool) slack.User {
		return slack.User{Deleted: deleted, Profile: slack.UserProfile{
			StatusText: text, StatusEmoji: emoji, StatusExpiration: int(exp),
		}}
	}
	cases := []struct {
		name string
		user slack.User
		want bool
	}{
		{"still has the status", user("On holiday", ":palm_tree:", applied.Expiration, false), true},
		{"the expiration has been moved by the user", user("On holiday", ":palm_tree:", applied.Expiration+86400, false), true},
		{"changed the text", user("Back soon", ":palm_tree:", applied.Expiration, false), false},
		{"changed the emoji", user("On holiday", ":sun:", applied.Expiration, false), false},
		{"cleared the status", user("", "", 0, false), false},
		{"the status has already expired", user("On holiday", ":palm_tree:", now.Unix()-1, false), false},
		{"deleted user", user("On holiday", ":palm_tree:", applied.Expiration, true), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ShouldClearStatus(c.user, applied, now); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func loadTestConfig(t *testing.T, yml string) {
	t.Helper()
	config.ClearAll()
	config.AddDriver(yaml.Driver)
	if err := config.LoadStrings(config.Yaml, yml); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(config.ClearAll)
}

func TestLoadPollerSettings(t *testing.T) {
	t.Run("config.yml-sample", func(t *testing.T) {
		b, err := os.ReadFile("../../config.yml-sample")
		if err != nil {
			t.Fatal(err)
		}
		loadTestConfig(t, string(b))
		s, err := loadPollerSettings()
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Types) == 0 || s.UnknownIcon == "" {
			t.Errorf("unexpected settings: %+v", s)
		}
		if s.Types["Vacation"].OrderNumber > s.Types["Sick"].OrderNumber {
			t.Error("Vacation must have higher priority than Sick")
		}
	})

	t.Run("invalid type definition", func(t *testing.T) {
		loadTestConfig(t, "unknown_type_icon: \":q:\"\ntypes:\n  - [\"Vacation\", \"On holiday\"]\n")
		if _, err := loadPollerSettings(); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("missing unknown_type_icon", func(t *testing.T) {
		loadTestConfig(t, "types:\n  - [\"Vacation\", \"On holiday\", \":palm_tree:\"]\n")
		if _, err := loadPollerSettings(); err == nil {
			t.Error("expected an error")
		}
	})
}

// SyncOrg scenarios with fake BambooHR and Slack APIs

type fakeBambooHR struct {
	employees   map[string]bamboohr.Employee
	timeOffs    []bamboohr.TimeOff
	holidays    map[string]bool
	holidaysErr error
	timeOffErr  error
	start, end  string
}

func (f *fakeBambooHR) GetEmployeeList() (map[string]bamboohr.Employee, error) {
	// SyncOrg modifies the map, so return a copy as the real client does.
	res := make(map[string]bamboohr.Employee)
	for k, v := range f.employees {
		res[k] = v
	}
	return res, nil
}

func (f *fakeBambooHR) GetEmployeeDirectory() (map[int]bamboohr.EmployeeInfo, error) {
	res := make(map[int]bamboohr.EmployeeInfo)
	for _, e := range f.employees {
		res[e.EmployeeID] = bamboohr.EmployeeInfo{ID: e.EmployeeID, Department: "Engineering"}
	}
	return res, nil
}

func (f *fakeBambooHR) TimeOffList(start string, end string) ([]bamboohr.TimeOff, error) {
	f.start, f.end = start, end
	return f.timeOffs, f.timeOffErr
}

func (f *fakeBambooHR) GetHolidays(string, string) (map[string]bool, error) {
	return f.holidays, f.holidaysErr
}

type statusCall struct {
	token, user, text, emoji string
	expiration               int64
}

type fakeSlack struct {
	token  string
	users  []slack.User
	setErr error
	calls  *[]statusCall
}

func (f *fakeSlack) GetUsers(...slack.GetUsersOption) ([]slack.User, error) {
	return f.users, nil
}

func (f *fakeSlack) SetUserCustomStatusWithUser(user, text, emoji string, exp int64) error {
	if f.setErr != nil {
		return f.setErr
	}
	*f.calls = append(*f.calls, statusCall{f.token, user, text, emoji, exp})
	return nil
}

type env struct {
	org     database.OrganizationCredentials
	bamboo  *fakeBambooHR
	slack   *fakeSlack
	calls   []statusCall
	clients OrgClients
}

// newEnv creates an isolated organization. Each Slack user is matched with a BambooHR employee by the email,
// the employee ID is the user's position in the list plus one.
func newEnv(t *testing.T, users ...slack.User) *env {
	e := &env{
		org:    database.OrganizationCredentials{SlackTeamID: "T" + t.Name(), SlackAdminUserID: "UADMIN"},
		bamboo: &fakeBambooHR{employees: map[string]bamboohr.Employee{}},
	}
	for i := range users {
		if users[i].Profile.Email == "" {
			users[i].Profile.Email = strings.ToLower(users[i].ID) + "@example.com"
		}
		e.bamboo.employees[users[i].Profile.Email] = bamboohr.Employee{
			EmployeeID: i + 1,
			Email:      users[i].Profile.Email,
		}
	}
	e.slack = &fakeSlack{token: "bot", users: users, calls: &e.calls}
	e.clients = OrgClients{
		BambooHR: e.bamboo,
		Slack:    e.slack,
		SlackForToken: func(token string) SlackAPI {
			return &fakeSlack{token: token, calls: &e.calls}
		},
	}
	return e
}

func (e *env) sync(t *testing.T) {
	t.Helper()
	if err := SyncOrg(e.org, e.clients, testSettings(), now); err != nil {
		t.Fatal(err)
	}
}

func (e *env) applied(t *testing.T) map[string]database.AppliedStatus {
	t.Helper()
	return database.GetAppliedStatuses(e.org.SlackTeamID)
}

func (e *env) setApplied(t *testing.T, userID string, s database.AppliedStatus) {
	t.Helper()
	if err := database.PutAppliedStatus(e.org.SlackTeamID, userID, s); err != nil {
		t.Fatal(err)
	}
}

func (e *env) expectCalls(t *testing.T, want ...statusCall) {
	t.Helper()
	if len(e.calls) != len(want) {
		t.Fatalf("got calls %+v, want %+v", e.calls, want)
	}
	for i := range want {
		if e.calls[i] != want[i] {
			t.Errorf("call %d: got %+v, want %+v", i, e.calls[i], want[i])
		}
	}
}

func vacationStatus(backDate string, tzOffset int) database.AppliedStatus {
	return database.AppliedStatus{Text: "On holiday", Emoji: ":palm_tree:", Expiration: expiresBefore(backDate, tzOffset)}
}

func withStatus(u slack.User, s database.AppliedStatus) slack.User {
	u.Profile.StatusText = s.Text
	u.Profile.StatusEmoji = s.Emoji
	u.Profile.StatusExpiration = int(s.Expiration)
	return u
}

func TestSyncOrg(t *testing.T) {
	t.Run("requests the time-offs for the lookahead window", func(t *testing.T) {
		e := newEnv(t)
		e.sync(t)
		if e.bamboo.start != "2026-11-12" || e.bamboo.end != "2027-01-12" {
			t.Errorf("got the %s - %s window", e.bamboo.start, e.bamboo.end)
		}
	})

	t.Run("sets the status until the end of the time off", func(t *testing.T) {
		e := newEnv(t, slack.User{ID: "U1", RealName: "Alice"})
		e.bamboo.timeOffs = []bamboohr.TimeOff{timeOff(1, "Vacation", "2026-11-12", "2026-11-13")}
		e.sync(t)
		want := vacationStatus("2026-11-14", 0)
		e.expectCalls(t, statusCall{"bot", "U1", want.Text, want.Emoji, want.Expiration})
		if got := e.applied(t)["U1"]; got != want {
			t.Errorf("applied status: got %+v, want %+v", got, want)
		}
		msg, err := database.GetWIOMessage(e.org.SlackTeamID)
		if err != nil {
			t.Fatal(err)
		}
		if len(msg) != 1 || msg[0].Employee.SlackUser.ID != "U1" || msg[0].Employee.Info.Department != "Engineering" ||
			msg[0].TimeOff.Type.BambooHRType != "Vacation" {
			t.Errorf("unexpected who-is-out message: %+v", msg)
		}
	})

	t.Run("overlapping time offs: the higher priority status is set", func(t *testing.T) {
		e := newEnv(t, slack.User{ID: "U1"})
		e.bamboo.timeOffs = []bamboohr.TimeOff{
			timeOff(1, "Sick", "2026-11-13"),
			timeOff(1, "Vacation", "2026-11-13"),
			timeOff(1, "Remote Work", "2026-11-13"),
		}
		e.sync(t)
		want := vacationStatus("2026-11-14", 0)
		e.expectCalls(t, statusCall{"bot", "U1", want.Text, want.Emoji, want.Expiration})
	})

	t.Run("back-to-back time offs of different types: today's type, expires at the end of both", func(t *testing.T) {
		e := newEnv(t, slack.User{ID: "U1"})
		e.bamboo.timeOffs = []bamboohr.TimeOff{
			timeOff(1, "Sick", "2026-11-12", "2026-11-13"),
			timeOff(1, "Vacation", "2026-11-14", "2026-11-15", "2026-11-16"),
		}
		e.sync(t)
		e.expectCalls(t, statusCall{"bot", "U1", "Out sick", ":face_with_thermometer:", expiresBefore("2026-11-17", 0)})
	})

	t.Run("time off on Friday and Monday: no status over the weekend", func(t *testing.T) {
		e := newEnv(t, slack.User{ID: "U1"})
		e.bamboo.timeOffs = []bamboohr.TimeOff{
			timeOff(1, "Vacation", "2026-11-13"),
			timeOff(1, "Vacation", "2026-11-16"),
		}
		e.sync(t)
		want := vacationStatus("2026-11-14", 0)
		e.expectCalls(t, statusCall{"bot", "U1", want.Text, want.Emoji, want.Expiration})
	})

	t.Run("a time off that includes the weekend in BambooHR", func(t *testing.T) {
		e := newEnv(t, slack.User{ID: "U1"})
		e.bamboo.timeOffs = []bamboohr.TimeOff{timeOff(1, "Vacation", "2026-11-13", "2026-11-14", "2026-11-15", "2026-11-16")}
		e.bamboo.timeOffs[0].Dates["2026-11-14"] = "0"
		e.bamboo.timeOffs[0].Dates["2026-11-15"] = "0"
		e.sync(t)
		want := vacationStatus("2026-11-17", 0)
		e.expectCalls(t, statusCall{"bot", "U1", want.Text, want.Emoji, want.Expiration})
	})

	t.Run("a holiday right after the time off extends the status", func(t *testing.T) {
		e := newEnv(t, slack.User{ID: "U1"})
		e.bamboo.timeOffs = []bamboohr.TimeOff{timeOff(1, "Vacation", "2026-11-12", "2026-11-13")}
		e.bamboo.holidays = map[string]bool{"2026-11-14": true}
		e.sync(t)
		want := vacationStatus("2026-11-15", 0)
		e.expectCalls(t, statusCall{"bot", "U1", want.Text, want.Emoji, want.Expiration})
	})

	t.Run("a holiday after the weekend doesn't extend the status", func(t *testing.T) {
		e := newEnv(t, slack.User{ID: "U1"})
		e.bamboo.timeOffs = []bamboohr.TimeOff{timeOff(1, "Vacation", "2026-11-13")}
		e.bamboo.holidays = map[string]bool{"2026-11-16": true}
		e.sync(t)
		want := vacationStatus("2026-11-14", 0)
		e.expectCalls(t, statusCall{"bot", "U1", want.Text, want.Emoji, want.Expiration})
	})

	t.Run("holidays are ignored when they cannot be loaded", func(t *testing.T) {
		e := newEnv(t, slack.User{ID: "U1"})
		e.bamboo.timeOffs = []bamboohr.TimeOff{timeOff(1, "Vacation", "2026-11-13")}
		e.bamboo.holidays = nil
		e.bamboo.holidaysErr = errors.New("forbidden")
		e.sync(t)
		want := vacationStatus("2026-11-14", 0)
		e.expectCalls(t, statusCall{"bot", "U1", want.Text, want.Emoji, want.Expiration})
	})

	t.Run("an unknown time off type uses the unknown icon", func(t *testing.T) {
		e := newEnv(t, slack.User{ID: "U1"})
		e.bamboo.timeOffs = []bamboohr.TimeOff{timeOff(1, "Jury Duty", "2026-11-13")}
		e.sync(t)
		e.expectCalls(t, statusCall{"bot", "U1", "Jury Duty", ":grey_question:", expiresBefore("2026-11-14", 0)})
	})

	t.Run("time zones decide whether the user is out today", func(t *testing.T) {
		e := newEnv(t,
			slack.User{ID: "UKIRITIMATI", TZOffset: 50400}, // already Saturday
			slack.User{ID: "UHONOLULU", TZOffset: -36000},  // Friday 00:00
		)
		e.bamboo.timeOffs = []bamboohr.TimeOff{
			timeOff(1, "Vacation", "2026-11-13"),
			timeOff(2, "Vacation", "2026-11-13"),
		}
		e.sync(t)
		want := vacationStatus("2026-11-14", -36000)
		e.expectCalls(t, statusCall{"bot", "UHONOLULU", want.Text, want.Emoji, want.Expiration})
	})

	t.Run("the status is skipped when it is actual", func(t *testing.T) {
		want := vacationStatus("2026-11-14", 0)
		e := newEnv(t, withStatus(slack.User{ID: "U1"}, want))
		e.bamboo.timeOffs = []bamboohr.TimeOff{timeOff(1, "Vacation", "2026-11-13")}
		e.sync(t)
		e.expectCalls(t)
		// It's remembered, so it can be cleared if the time off is withdrawn.
		if got := e.applied(t)["U1"]; got != want {
			t.Errorf("applied status: got %+v, want %+v", got, want)
		}
	})

	t.Run("the user has moved to another time zone", func(t *testing.T) {
		old := vacationStatus("2026-11-14", 0)
		e := newEnv(t, withStatus(slack.User{ID: "U1", TZOffset: 7200}, old))
		e.setApplied(t, "U1", old)
		e.bamboo.timeOffs = []bamboohr.TimeOff{timeOff(1, "Vacation", "2026-11-13")}
		e.sync(t)
		want := vacationStatus("2026-11-14", 7200)
		e.expectCalls(t, statusCall{"bot", "U1", want.Text, want.Emoji, want.Expiration})
		if got := e.applied(t)["U1"]; got != want {
			t.Errorf("applied status: got %+v, want %+v", got, want)
		}
	})

	t.Run("the time off has been extended", func(t *testing.T) {
		old := vacationStatus("2026-11-14", 0)
		e := newEnv(t, withStatus(slack.User{ID: "U1"}, old))
		e.setApplied(t, "U1", old)
		e.bamboo.timeOffs = []bamboohr.TimeOff{timeOff(1, "Vacation", "2026-11-13", "2026-11-14", "2026-11-15")}
		e.sync(t)
		want := vacationStatus("2026-11-16", 0)
		e.expectCalls(t, statusCall{"bot", "U1", want.Text, want.Emoji, want.Expiration})
	})

	t.Run("the time off has been shortened", func(t *testing.T) {
		old := vacationStatus("2026-11-18", 0)
		e := newEnv(t, withStatus(slack.User{ID: "U1"}, old))
		e.setApplied(t, "U1", old)
		e.bamboo.timeOffs = []bamboohr.TimeOff{timeOff(1, "Vacation", "2026-11-13")}
		e.sync(t)
		want := vacationStatus("2026-11-14", 0)
		e.expectCalls(t, statusCall{"bot", "U1", want.Text, want.Emoji, want.Expiration})
	})

	t.Run("the user has replaced the status during the time off", func(t *testing.T) {
		e := newEnv(t, withStatus(slack.User{ID: "U1"}, database.AppliedStatus{Text: "Lunch", Emoji: ":taco:"}))
		e.setApplied(t, "U1", vacationStatus("2026-11-14", 0))
		e.bamboo.timeOffs = []bamboohr.TimeOff{timeOff(1, "Vacation", "2026-11-13")}
		e.sync(t)
		want := vacationStatus("2026-11-14", 0)
		e.expectCalls(t, statusCall{"bot", "U1", want.Text, want.Emoji, want.Expiration})
	})

	t.Run("the time off has been withdrawn", func(t *testing.T) {
		old := vacationStatus("2026-11-18", 0)
		e := newEnv(t, withStatus(slack.User{ID: "U1"}, old))
		e.setApplied(t, "U1", old)
		e.sync(t)
		e.expectCalls(t, statusCall{"bot", "U1", "", "", 0})
		if _, ok := e.applied(t)["U1"]; ok {
			t.Error("the applied status must be forgotten")
		}
		msg, _ := database.GetWIOMessage(e.org.SlackTeamID)
		if len(msg) != 0 {
			t.Errorf("unexpected who-is-out message: %+v", msg)
		}
	})

	t.Run("the time off has been withdrawn, but the user has changed the status", func(t *testing.T) {
		e := newEnv(t, withStatus(slack.User{ID: "U1"}, database.AppliedStatus{
			Text: "In a meeting", Emoji: ":calendar:", Expiration: now.Unix() + 3600,
		}))
		e.setApplied(t, "U1", vacationStatus("2026-11-18", 0))
		e.sync(t)
		e.expectCalls(t)
		if _, ok := e.applied(t)["U1"]; ok {
			t.Error("the applied status must be forgotten")
		}
	})

	t.Run("the time off is over and Slack has already cleared the status", func(t *testing.T) {
		e := newEnv(t, slack.User{ID: "U1"})
		e.setApplied(t, "U1", vacationStatus("2026-11-13", 0))
		e.sync(t)
		e.expectCalls(t)
		if _, ok := e.applied(t)["U1"]; ok {
			t.Error("the applied status must be forgotten")
		}
	})

	t.Run("the user has left the workspace", func(t *testing.T) {
		e := newEnv(t)
		e.setApplied(t, "UGONE", vacationStatus("2026-11-18", 0))
		e.sync(t)
		e.expectCalls(t)
		if _, ok := e.applied(t)["UGONE"]; ok {
			t.Error("the applied status must be forgotten")
		}
	})

	t.Run("a failed update is retried on the next run", func(t *testing.T) {
		e := newEnv(t, slack.User{ID: "U1"})
		e.bamboo.timeOffs = []bamboohr.TimeOff{timeOff(1, "Vacation", "2026-11-13")}
		e.slack.setErr = errors.New("ratelimited")
		e.sync(t)
		if _, ok := e.applied(t)["U1"]; ok {
			t.Error("a status that hasn't been set must not be remembered")
		}
		e.slack.setErr = nil
		e.sync(t)
		want := vacationStatus("2026-11-14", 0)
		e.expectCalls(t, statusCall{"bot", "U1", want.Text, want.Emoji, want.Expiration})
	})

	t.Run("users who are not in both Slack and BambooHR are ignored", func(t *testing.T) {
		e := newEnv(t, slack.User{ID: "U1"})
		delete(e.bamboo.employees, "u1@example.com")
		e.bamboo.employees["nobody@example.com"] = bamboohr.Employee{EmployeeID: 2, Email: "nobody@example.com"}
		e.bamboo.timeOffs = []bamboohr.TimeOff{
			timeOff(1, "Vacation", "2026-11-13"),
			timeOff(2, "Vacation", "2026-11-13"),
		}
		e.sync(t)
		e.expectCalls(t)
	})

	t.Run("admins' statuses are set with their own tokens", func(t *testing.T) {
		e := newEnv(t,
			slack.User{ID: "UOWNER", IsOwner: true},
			slack.User{ID: "UNOTOKEN", IsAdmin: true},
			slack.User{ID: "UADMIN", IsAdmin: true}, // installed the app
		)
		if err := database.PutSlackUserToken(e.org.SlackTeamID, "UOWNER",
			database.SlackToken{AccessToken: "owner-token"}); err != nil {
			t.Fatal(err)
		}
		e.bamboo.timeOffs = []bamboohr.TimeOff{
			timeOff(1, "Vacation", "2026-11-13"),
			timeOff(2, "Vacation", "2026-11-13"),
			timeOff(3, "Vacation", "2026-11-13"),
		}
		e.sync(t)
		want := vacationStatus("2026-11-14", 0)
		got := map[string]statusCall{}
		for _, c := range e.calls {
			got[c.user] = c
		}
		if len(got) != 2 {
			t.Fatalf("got calls %+v", e.calls)
		}
		if got["UOWNER"] != (statusCall{"owner-token", "UOWNER", want.Text, want.Emoji, want.Expiration}) {
			t.Errorf("owner: got %+v", got["UOWNER"])
		}
		if got["UADMIN"] != (statusCall{"bot", "UADMIN", want.Text, want.Emoji, want.Expiration}) {
			t.Errorf("admin: got %+v", got["UADMIN"])
		}
		if _, ok := e.applied(t)["UNOTOKEN"]; ok {
			t.Error("a status that hasn't been set must not be remembered")
		}
	})

	t.Run("BambooHR errors abort the sync", func(t *testing.T) {
		old := vacationStatus("2026-11-18", 0)
		e := newEnv(t, withStatus(slack.User{ID: "U1"}, old))
		e.setApplied(t, "U1", old)
		e.bamboo.timeOffErr = errors.New("unavailable")
		if err := SyncOrg(e.org, e.clients, testSettings(), now); err == nil {
			t.Fatal("expected an error")
		}
		// Statuses must not be cleared because of a BambooHR outage.
		e.expectCalls(t)
		if _, ok := e.applied(t)["U1"]; !ok {
			t.Error("the applied status must be kept")
		}
	})
}
