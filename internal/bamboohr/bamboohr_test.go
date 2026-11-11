package bamboohr

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// newTestClient creates a client for a fake BambooHR API that serves the response for the path.
func newTestClient(t *testing.T, path string, status int, body string, check func(r *http.Request)) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			t.Errorf("unexpected path %s, want %s", r.URL.Path, path)
		}
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("secret:x"))
		if r.Header.Get("Authorization") != want {
			t.Errorf("unexpected Authorization header %q", r.Header.Get("Authorization"))
		}
		if check != nil {
			check(r)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c := New("acme", "secret")
	c.endpoint = srv.URL
	c.httpclient = srv.Client()
	return c
}

func TestNew(t *testing.T) {
	c := New("acme", "secret")
	if c.endpoint != "https://api.bamboohr.com/api/gateway.php/acme" {
		t.Errorf("unexpected endpoint %s", c.endpoint)
	}
}

func TestGetEmployeeList(t *testing.T) {
	c := newTestClient(t, "/v1/meta/users/", http.StatusOK, `{
		"1": {"id": 1, "employeeId": 10, "firstName": "Alice", "email": "alice@example.com", "status": "enabled"},
		"2": {"id": 2, "employeeId": 20, "firstName": "Bob", "email": "bob@example.com", "status": "disabled"}
	}`, nil)
	list, err := c.GetEmployeeList()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list["alice@example.com"].EmployeeID != 10 {
		t.Errorf("disabled employees must be skipped, got %+v", list)
	}
}

func TestGetEmployeeDirectory(t *testing.T) {
	c := newTestClient(t, "/v1/employees/directory/", http.StatusOK, `{
		"fields": [],
		"employees": [{"id": "10", "firstName": "Alice", "department": "Engineering", "jobTitle": "Engineer"}]
	}`, nil)
	dir, err := c.GetEmployeeDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if dir[10].Department != "Engineering" || dir[10].JobTitle != "Engineer" {
		t.Errorf("unexpected directory %+v", dir)
	}
}

func TestTimeOffList(t *testing.T) {
	c := newTestClient(t, "/v1/time_off/requests/", http.StatusOK, `[{
		"id": "1", "employeeId": "10", "name": "Alice",
		"start": "2026-11-13", "end": "2026-11-16",
		"status": {"status": "approved", "lastChangedByUserId": "2"},
		"type": {"id": "3", "name": "Vacation"},
		"amount": {"unit": "days", "amount": "2"},
		"dates": {"2026-11-13": "1", "2026-11-14": "0", "2026-11-15": "0", "2026-11-16": "1"}
	}]`, func(r *http.Request) {
		q := r.URL.Query()
		if q.Get("status") != "approved" || q.Get("start") != "2026-11-12" || q.Get("end") != "2027-01-12" {
			t.Errorf("unexpected query %s", r.URL.RawQuery)
		}
	})
	list, err := c.TimeOffList("2026-11-12", "2027-01-12")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d time-offs", len(list))
	}
	to := list[0]
	if to.EmployeeID != 10 || to.Type.Name != "Vacation" || len(to.Dates) != 4 || to.Amount.Amount != 2 {
		t.Errorf("unexpected time off %+v", to)
	}
}

func TestGetHolidays(t *testing.T) {
	c := newTestClient(t, "/v1/time_off/whos_out/", http.StatusOK, `[
		{"id": 1, "type": "timeOff", "employeeId": 10, "name": "Alice", "start": "2026-11-13", "end": "2026-11-13"},
		{"id": 2, "type": "holiday", "name": "Thanksgiving", "start": "2026-11-26", "end": "2026-11-27"},
		{"id": 3, "type": "holiday", "name": "Christmas", "start": "2026-12-25", "end": "2026-12-25"},
		{"id": 4, "type": "holiday", "name": "Broken", "start": "soon", "end": "2026-12-31"}
	]`, func(r *http.Request) {
		if r.URL.Query().Get("start") != "2026-11-12" || r.URL.Query().Get("end") != "2027-01-12" {
			t.Errorf("unexpected query %s", r.URL.RawQuery)
		}
	})
	got, err := c.GetHolidays("2026-11-12", "2027-01-12")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"2026-11-26": true, "2026-11-27": true, "2026-12-25": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestGetDepartments(t *testing.T) {
	c := newTestClient(t, "/v1/meta/lists", http.StatusOK, `[
		{"fieldId": "4", "name": "Department", "options": [
			{"id": 1, "name": "Engineering", "archived": "no"},
			{"id": 2, "name": "Legacy", "archived": "yes"}
		]},
		{"fieldId": 5, "name": "Division", "options": [{"id": 3, "name": "EMEA", "archived": "no"}]}
	]`, nil)
	got, err := c.GetDepartments()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[int]string{1: "Engineering"}) {
		t.Errorf("unexpected departments %v", got)
	}
}

func TestErrors(t *testing.T) {
	t.Run("HTTP error", func(t *testing.T) {
		c := newTestClient(t, "/v1/time_off/requests/", http.StatusUnauthorized, ``, nil)
		if _, err := c.TimeOffList("2026-11-12", "2026-11-13"); err == nil {
			t.Error("expected an error")
		}
	})
	t.Run("invalid JSON", func(t *testing.T) {
		c := newTestClient(t, "/v1/time_off/whos_out/", http.StatusOK, `{"not": "a list"}`, nil)
		if _, err := c.GetHolidays("2026-11-12", "2026-11-13"); err == nil {
			t.Error("expected an error")
		}
	})
	t.Run("no departments", func(t *testing.T) {
		c := newTestClient(t, "/v1/meta/lists", http.StatusOK, `[]`, nil)
		if _, err := c.GetDepartments(); err == nil {
			t.Error("expected an error")
		}
	})
}
