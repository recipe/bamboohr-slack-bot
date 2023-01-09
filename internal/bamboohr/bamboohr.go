package bamboohr

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/slack-go/slack"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type TBool bool
type TDisabled bool
type IntString int

// UnmarshalJSON helps to avoid an error with int types when they appear as strings in the JSON due to a bad API design.
func (s *IntString) UnmarshalJSON(data []byte) error {
	var i int
	if err := json.Unmarshal(data, &i); err != nil {
		// Trying to parse as string
		var str string
		if e := json.Unmarshal(data, &str); e != nil {
			return err
		}
		i64, err := strconv.ParseInt(str, 10, 64)
		if err != nil {
			return err
		}
		i = int(i64)
	}
	*s = IntString(i)
	return nil
}

// UnmarshalJSON parses boolean values that are provided as following: "disabled" (true) / "enabled" (false)
func (s *TDisabled) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	if str == "disabled" {
		*s = true
	} else {
		*s = false
	}
	return nil
}

// UnmarshalJSON parses boolean values that are provided as following: "yes" (true) / "no" (false)
func (s *TBool) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	if str == "yes" {
		*s = true
	} else {
		*s = false
	}
	return nil
}

type Employee struct {
	ID         int           `json:"id"`
	EmployeeID int           `json:"employeeId"`
	FirstName  string        `json:"firstName"`
	LastName   string        `json:"lastName"`
	Email      string        `json:"email"`
	Disabled   TDisabled     `json:"status"`
	LastLogin  time.Time     `json:"lastLogin"`
	SlackUser  slack.User    `json:"-"`
	Info       *EmployeeInfo `json:"-"`
}

type TimeOffStatus struct {
	LastChanged         string `json:"lastChanged"`
	LastChangedByUserID int    `json:"lastChangedByUserId,string"`
	Status              string `json:"status"`
}

type TimeOffType struct {
	ID   int    `json:"id,string"`
	Name string `json:"name"`
	Icon string `json:"icon"`
}

type Amount struct {
	Unit   string `json:"unit"`
	Amount int    `json:"amount,string"`
}

type Actions struct {
	View    bool `json:"view"`
	Edit    bool `json:"edit"`
	Cancel  bool `json:"cancel"`
	Approve bool `json:"approve"`
	Deny    bool `json:"deny"`
	Bypass  bool `json:"bypass"`
}

type TimeOffDates map[string]json.Number

type Notes struct {
	Manager  string `json:"manager,omitempty"`
	Employee string `json:"employee,omitempty"`
}

type TimeOff struct {
	ID         int           `json:"id,string"`
	EmployeeID int           `json:"employeeId,string"`
	Status     TimeOffStatus `json:"status"`
	FullName   string        `json:"name"`
	Start      string        `json:"start"`
	End        string        `json:"end"`
	Created    string        `json:"created"`
	Type       TimeOffType   `json:"type"`
	Amount     Amount        `json:"amount"`
	Actions    Actions       `json:"actions"`
	Dates      TimeOffDates  `json:"dates"`
	Notes      Notes         `json:"notes"`
}

type MetaFieldOption struct {
	ID           int       `json:"id"`
	Archived     TBool     `json:"archived"`
	CreatedDate  time.Time `json:"createdDate,omitempty"`
	ArchivedDate time.Time `json:"archivedDate,omitempty"`
	Name         string    `json:"name"`
}

type MetaField struct {
	FieldID    IntString         `json:"fieldId"`
	Manageable TBool             `json:"manageable"`
	Multiple   TBool             `json:"multiple"`
	Name       string            `json:"name"`
	Options    []MetaFieldOption `json:"options"`
	Alias      string            `json:"alias"`
}

type FieldType struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

type EmployeeInfo struct {
	ID         int    `json:"id,string"`
	FirstName  string `json:"firstName"`
	LastName   string `json:"lastName"`
	JobTitle   string `json:"jobTitle"`
	Department string `json:"department"`
	Division   string `json:"division"`
}

type EmployeeDirectoryResponse struct {
	Fields    []FieldType    `json:"fields"`
	Employees []EmployeeInfo `json:"employees"`
}

const APIURL = "https://api.bamboohr.com/api/gateway.php/%s"

type httpClient interface {
	Do(*http.Request) (*http.Response, error)
}

type Client struct {
	org        string
	token      string
	endpoint   string
	httpclient httpClient
}

type RequestContext struct {
	method   string
	endpoint string
	query    url.Values
}

func New(org string, token string) *Client {
	s := &Client{
		org:        token,
		token:      token,
		endpoint:   fmt.Sprintf(APIURL, org),
		httpclient: &http.Client{Timeout: 10 * time.Second},
	}
	return s
}

func (api *Client) request(ctx RequestContext, s interface{}) error {
	req, err := http.NewRequest(ctx.method, fmt.Sprintf("%s%s", api.endpoint, ctx.endpoint), nil)
	if err != nil {
		return fmt.Errorf("unable to initialize an HTTP client. %v", err)
	}
	req.Header = http.Header{
		"Authorization":  {"Basic " + base64.StdEncoding.EncodeToString([]byte(api.token+":x"))},
		"Accept":         {"application/json"},
		"Accept-Charset": {"utf-8"},
	}
	if nil != ctx.query {
		req.URL.RawQuery = ctx.query.Encode()
	}
	res, err := api.httpclient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		err = json.NewDecoder(res.Body).Decode(&s)
		if err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("server responded with the HTTP %d status", res.StatusCode)
}

// GetEmployeeList returns the list of employees with their email addresses as keys
func (api *Client) GetEmployeeList() (map[string]Employee, error) {
	ctx := RequestContext{
		method:   "GET",
		endpoint: "/v1/meta/users/",
	}
	var j map[string]Employee
	err := api.request(ctx, &j)
	if err != nil {
		return nil, err
	}
	result := make(map[string]Employee)
	for _, row := range j {
		if !row.Disabled {
			result[row.Email] = row
		}
	}
	return result, nil
}

// GetEmployeeDirectory retrieves a list of employees with links to the departments, divisions and job titles.
// Employee identifiers are used as the keys.
func (api *Client) GetEmployeeDirectory() (map[int]EmployeeInfo, error) {
	ctx := RequestContext{
		method:   "GET",
		endpoint: "/v1/employees/directory/",
	}
	var r EmployeeDirectoryResponse
	err := api.request(ctx, &r)
	if err != nil {
		return nil, err
	}
	result := make(map[int]EmployeeInfo)
	for _, row := range r.Employees {
		result[row.ID] = row
	}
	return result, nil
}

func (api *Client) TimeOffList(startDate string, endDate string) ([]TimeOff, error) {
	ctx := RequestContext{
		method:   "GET",
		endpoint: "/v1/time_off/requests/",
		query: url.Values{
			"status": {"approved"},
			"start":  {startDate},
			"end":    {endDate},
		},
	}
	var result []TimeOff
	err := api.request(ctx, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (api *Client) GetMetaFieldList() ([]MetaField, error) {
	ctx := RequestContext{
		method:   "GET",
		endpoint: "/v1/meta/lists",
	}
	var result []MetaField
	err := api.request(ctx, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetDepartments get a list of departments
func (api *Client) GetDepartments() (map[int]string, error) {
	res := make(map[int]string)
	list, err := api.GetMetaFieldList()
	if err != nil {
		return res, err
	}
	for _, f := range list {
		if f.Name != "Department" {
			continue
		}
		for _, opt := range f.Options {
			if !opt.Archived {
				res[opt.ID] = opt.Name
			}
		}
	}
	if len(res) == 0 {
		return res, fmt.Errorf("cannot get a list of departments")
	}

	return res, nil
}
