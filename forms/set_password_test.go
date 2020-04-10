package forms

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/moapis/ehtml"
)

const defaultSetPWTmplOut = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>Set password</title>
</head>
<body>
	<h1>Set a new password</h1>
	<form method="post" action="/setpw?redirect=http://example.com/foo?hello=world&amp;jwt=xxxxxxxx">
		<input type="password" placeholder="Password" name="password" required>
		<button type="submit">Submit</button>
	</form>
</body>
</html>`

const setPWBadRequestOut = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>400 Bad Request: Missing token in URL</title>
</head>
<body>
	<h1>400 Bad Request</h1>
	<p>Missing token in URL</p>
</body>
</html>`

func TestForms_setPWGet(t *testing.T) {
	tests := []struct {
		name     string
		r        *http.Request
		EP       ehtml.Pages
		wantCode int
		want     string
	}{
		{
			"Missing JWT",
			httptest.NewRequest("GET", "/login", nil),
			ehtml.Pages{},
			http.StatusBadRequest,
			setPWBadRequestOut,
		},
		{
			"Error page error",
			httptest.NewRequest("GET", "/login", nil),
			ehtml.Pages{Tmpl: epErrTmpl},
			http.StatusInternalServerError,
			"500 Internal server error. While handling:\n400 Bad Request: Missing token in URL",
		},
		{
			"Success",
			httptest.NewRequest("GET", "/setpw?redirect=http://example.com/foo?hello=world&jwt=xxxxxxxx", nil),
			ehtml.Pages{},
			http.StatusOK,
			defaultSetPWTmplOut,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Forms{
				EP: tt.EP,
			}

			w := httptest.NewRecorder()

			f.setPWGet(w, tt.r)

			resp := w.Result()
			body, _ := ioutil.ReadAll(resp.Body)

			if resp.StatusCode != tt.wantCode {
				t.Errorf("Forms.setPWGet() status = %v, want: %v", resp.StatusCode, tt.wantCode)
			}

			got := string(body)
			if got != tt.want {
				t.Errorf("Forms.setPWGet() = \n%v\nwant\n%v", got, tt.want)
			}
		})
	}
}

const setPWOKOut = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>200 OK: Password set succesfully. You can now close this window</title>
</head>
<body>
	<h1>200 OK</h1>
	<p>Password set succesfully. You can now close this window</p>
</body>
</html>`

func TestForms_setPWRedirect(t *testing.T) {
	f := &Forms{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/setpw?redirect=http://example.com/foo?hello=world&jwt=xxxxxxxx", nil)
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	f.setPWRedirect(w, r)

	resp := w.Result()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Forms.setPWRedirect() status = %v, want: %v", resp.StatusCode, http.StatusSeeOther)
	}

	want := "/login?redirect=http://example.com/foo?hello=world"
	if got := resp.Header.Get("Location"); got != want {
		t.Errorf("Forms.setPWRedirect() Location = %v, want: %v", got, want)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/setpw?jwt=xxxxxxxx", nil)
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	f.setPWRedirect(w, r)

	resp = w.Result()
	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Forms.setPWRedirect() status = %v, want: %v", resp.StatusCode, http.StatusOK)
	}

	want = setPWOKOut
	if got := string(body); got != want {
		t.Errorf("Forms.setPWRedirect() Body = %v, want: %v", got, want)
	}
}
