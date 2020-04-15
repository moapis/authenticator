package forms

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/moapis/authenticator"
	"github.com/moapis/ehtml"
	"google.golang.org/grpc"
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

const setPWFlashOut = `<!DOCTYPE html>
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
	<p>%s</p>
</body>
</html>`

const invalidTknOut = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>401 Unauthorized: Token verification failed, please request a new one.</title>
</head>
<body>
	<h1>401 Unauthorized</h1>
	<p>Token verification failed, please request a new one.</p>
</body>
</html>`

func TestForms_setPWPost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cc, err := grpc.DialContext(ctx, "127.0.0.1:8765", grpc.WithBlock(), grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	ectx, cancel := context.WithCancel(ctx)
	cancel()

	tests := []struct {
		name     string
		r        *http.Request
		ctx      context.Context
		wantCode int
		wantBody string
		wantLoc  string
	}{
		{
			"Malformed body",
			httptest.NewRequest("POST", "/setpw?redirect=http://example.com/foo?hello=world&jwt=xxxxxxxx", strings.NewReader("%sssssssss")),
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(setPWFlashOut, "error: Malformed form data"),
			"",
		},
		{
			"Missing token",
			httptest.NewRequest("POST", "/setpw?redirect=http://example.com/foo?hello=world", strings.NewReader("password=admin")),
			ctx,
			http.StatusBadRequest,
			setPWBadRequestOut,
			"",
		},
		{
			"Mssing password",
			httptest.NewRequest("POST", "/setpw?redirect=http://example.com/foo?hello=world&jwt=xxxxxxxx", strings.NewReader("")),
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(setPWFlashOut, "error: Missing form data: password"),
			"",
		},
		{
			"Internal server error",
			httptest.NewRequest("POST", "/setpw?redirect=http://example.com/foo?hello=world&jwt=xxxxxxxx", strings.NewReader("password=admin")),
			ectx,
			http.StatusInternalServerError,
			fmt.Sprintf(setPWFlashOut, "error: Internal server error"),
			"",
		},
		{
			"Invalid token",
			httptest.NewRequest("POST", "/setpw?redirect=http://example.com/foo?hello=world&jwt=xxxxxxxx", strings.NewReader("password=admin")),
			ctx,
			http.StatusUnauthorized,
			invalidTknOut,
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Forms{
				Client: auth.NewAuthenticatorClient(cc),
			}
			w := httptest.NewRecorder()

			tt.r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			r := tt.r.WithContext(tt.ctx)

			f.setPWPost(w, r)

			resp := w.Result()
			body, _ := ioutil.ReadAll(resp.Body)

			if resp.StatusCode != tt.wantCode {
				t.Errorf("Forms.setPWPost() status = %v, want: %v", resp.StatusCode, tt.wantCode)
			}

			if got := string(body); got != tt.wantBody {
				t.Errorf("Forms.setPWPost() = \n%v\nwant\n%v", got, tt.wantBody)
			}

			if got := resp.Header.Get("Location"); !strings.HasPrefix(got, tt.wantLoc) {
				t.Errorf("Forms.setPWPost() Location = %v, want: %v", got, tt.wantLoc)
			}
		})
	}
}

func TestForms_SetPWHandler(t *testing.T) {
	f := &Forms{}
	f.SetPWHandler()
}

func Test_setPWHandler_ServeHTTP(t *testing.T) {
	h := setPWHandler{Forms: &Forms{}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/setpw?redirect=http://example.com/foo?hello=world&jwt=xxxxxxxx", nil)

	h.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("setPWHandler.ServeHTTP() GET status = %v, want: %v", resp.StatusCode, http.StatusOK)
	}

	if got := string(body); got != defaultSetPWTmplOut {
		t.Errorf("setPWHandler.ServeHTTP() GET = \n%v\nwant\n%v", got, defaultSetPWTmplOut)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/setpw?redirect=http://example.com/foo?hello=world", strings.NewReader("password=admin"))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	h.ServeHTTP(w, r)

	resp = w.Result()
	body, _ = ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("setPWHandler.ServeHTTP() POST status = %v, want: %v", resp.StatusCode, http.StatusBadRequest)
	}

	if got := string(body); got != setPWBadRequestOut {
		t.Errorf("setPWHandler.ServeHTTP() POST = \n%v\nwant\n%v", got, setPWBadRequestOut)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest("PUT", "/setpw?redirect=http://example.com/foo?hello=world", strings.NewReader("password=admin"))

	h.ServeHTTP(w, r)

	resp = w.Result()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("setPWHandler.ServeHTTP() POP status = %v, want: %v", resp.StatusCode, http.StatusMethodNotAllowed)
	}

	want := "GET POST"
	if got := resp.Header.Get("Allow"); !strings.HasPrefix(got, want) {
		t.Errorf("setPWHandler.ServeHTTP() Allow = %v, want: %v", got, want)
	}
}
