package bamboohr

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/slack-go/slack"
	"net/http"
	"net/url"
	"time"
)

type TBool bool

func (s *TBool) UnmarshalJSON(data []byte) error {
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

type Employee struct {
	ID         int        `json:"id"`
	EmployeeID int        `json:"employeeId"`
	FirstName  string     `json:"firstName"`
	LastName   string     `json:"lastName"`
	Email      string     `json:"email"`
	Disabled   TBool      `json:"status"`
	LastLogin  time.Time  `json:"lastLogin"`
	SlackUser  slack.User `json:"-"`
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
	var result map[string]Employee
	result = make(map[string]Employee)
	for _, row := range j {
		if !row.Disabled {
			result[row.Email] = row
		}
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
