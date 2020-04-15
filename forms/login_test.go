package forms

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/moapis/authenticator"
	"google.golang.org/grpc"
)

const defaultLoginTmplOut = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>Please login</title>
</head>
<body>
	<h1>Please login</h1>
	<form method="post" action="/login?redirect=http://example.com/foo?hello=world">
		<input type="email" placeholder="Email" name="email" required>
		<input type="password" placeholder="Password" name="password" required>
		<button type="submit">Sign In</button>
	</form>
	<p><a href="/reset-password?redirect=http://example.com/foo?hello=world">Password reset</a></p>
</body>
</html>`

const loginBadRequestOut = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>400 Bad Request: Missing redirect in URL</title>
</head>
<body>
	<h1>400 Bad Request</h1>
	<p>Missing redirect in URL</p>
</body>
</html>`

func TestForms_loginGet(t *testing.T) {
	tests := []struct {
		name     string
		r        *http.Request
		wantCode int
		want     string
	}{
		{
			"Missing redirect",
			httptest.NewRequest("GET", "/login", nil),
			http.StatusBadRequest,
			loginBadRequestOut,
		},
		{
			"Success",
			httptest.NewRequest("GET", "/login?redirect=http://example.com/foo?hello=world", nil),
			http.StatusOK,
			defaultLoginTmplOut,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Forms{}

			w := httptest.NewRecorder()

			f.loginGet(w, tt.r)

			resp := w.Result()
			body, _ := ioutil.ReadAll(resp.Body)

			if resp.StatusCode != tt.wantCode {
				t.Errorf("Forms.formHandler() status = %v, want: %v", resp.StatusCode, tt.wantCode)
			}

			got := string(body)
			if got != tt.want {
				t.Errorf("Forms.formHandler() = \n%v\nwant\n%v", got, tt.want)
			}
		})
	}
}

func TestForms_loginRedirect(t *testing.T) {
	f := &Forms{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/login?redirect=http://example.com/foo?hello=world", nil)
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	u, err := url.Parse("http://example.com/foo?hello=world")
	if err != nil {
		t.Fatal(err)
	}

	f.loginRedirect(w, r, u, "spanac")

	resp := w.Result()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Forms.formHandler() status = %v, want: %v", resp.StatusCode, http.StatusSeeOther)
	}

	want := "http://example.com/foo?hello=world&jwt=spanac"
	if got := resp.Header.Get("Location"); got != want {
		t.Errorf("Forms.formHandler() Location = %v, want: %v", got, want)
	}
}

const loginFlashOut = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>Please login</title>
</head>
<body>
	<h1>Please login</h1>
	<form method="post" action="/login?redirect=http://example.com/foo?hello=world">
		<input type="email" placeholder="Email" name="email" required>
		<input type="password" placeholder="Password" name="password" required>
		<button type="submit">Sign In</button>
	</form>
	<p>%s</p>
	<p><a href="/reset-password?redirect=http://example.com/foo?hello=world">Password reset</a></p>
</body>
</html>`

func TestForms_loginPost(t *testing.T) {
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
			httptest.NewRequest("POST", "/login?redirect=http://example.com/foo?hello=world", strings.NewReader("%sssssssss")),
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(loginFlashOut, "error: Malformed form data"),
			"",
		},
		{
			"Missing redirect",
			httptest.NewRequest("POST", "/login", strings.NewReader("email=admin%40localhost&password=admin")),
			ctx,
			http.StatusBadRequest,
			loginBadRequestOut,
			"",
		},
		{
			"No body",
			httptest.NewRequest("POST", "/login?redirect=http://example.com/foo?hello=world", nil),
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(loginFlashOut, "error: Missing form data: Email and Password"),
			"",
		},
		{
			"Succes and redirect",
			httptest.NewRequest("POST", "/login?redirect=http://example.com/foo?hello=world", strings.NewReader("email=admin%40localhost&password=admin")),
			ctx,
			http.StatusSeeOther,
			"",
			"http://example.com/foo?hello=world&jwt=",
		},
		{
			"Internal server error",
			httptest.NewRequest("POST", "/login?redirect=http://example.com/foo?hello=world", strings.NewReader("email=admin%40localhost&password=admin")),
			ectx,
			http.StatusInternalServerError,
			fmt.Sprintf(loginFlashOut, "error: Internal server error"),
			"",
		},
		{
			"Wrong email or password",
			httptest.NewRequest("POST", "/login?redirect=http://example.com/foo?hello=world", strings.NewReader("email=admin%40localhost&password=wrong")),
			ctx,
			http.StatusUnauthorized,
			fmt.Sprintf(loginFlashOut, "error: Wrong email or password"),
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

			f.loginPost(w, r)

			resp := w.Result()
			body, _ := ioutil.ReadAll(resp.Body)

			if resp.StatusCode != tt.wantCode {
				t.Errorf("Forms.postHandler() status = %v, want: %v", resp.StatusCode, tt.wantCode)
			}

			if got := string(body); got != tt.wantBody {
				t.Errorf("Forms.postHandler() = \n%v\nwant\n%v", got, tt.wantBody)
			}

			if got := resp.Header.Get("Location"); !strings.HasPrefix(got, tt.wantLoc) {
				t.Errorf("Forms.postHandler() Location = %v, want: %v", got, tt.wantLoc)
			}
		})
	}
}

func Test_loginHandler_ServeHTTP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cc, err := grpc.DialContext(ctx, "127.0.0.1:8765", grpc.WithBlock(), grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	f := &Forms{Client: auth.NewAuthenticatorClient(cc)}
	h := f.LoginHander()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/login?redirect=http://example.com/foo?hello=world", nil)

	h.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("loginHandler.ServeHTTP() GET status = %v, want: %v", resp.StatusCode, http.StatusOK)
	}

	if got := string(body); got != defaultLoginTmplOut {
		t.Errorf("loginHandler.ServeHTTP() GET = \n%v\nwant\n%v", got, defaultLoginTmplOut)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/login?redirect=http://example.com/foo?hello=world", strings.NewReader("email=admin%40localhost&password=admin"))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	h.ServeHTTP(w, r)

	resp = w.Result()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("loginHandler.ServeHTTP() POST status = %v, want: %v", resp.StatusCode, http.StatusSeeOther)
	}

	want := "http://example.com/foo?hello=world&jwt="
	if got := resp.Header.Get("Location"); !strings.HasPrefix(got, want) {
		t.Errorf("loginHandler.ServeHTTP() Location = %v, want: %v", got, want)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest("PUT", "/login?redirect=http://example.com/foo?hello=world", nil)

	h.ServeHTTP(w, r)

	resp = w.Result()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("loginHandler.ServeHTTP() POP status = %v, want: %v", resp.StatusCode, http.StatusMethodNotAllowed)
	}

	want = "GET POST"
	if got := resp.Header.Get("Allow"); !strings.HasPrefix(got, want) {
		t.Errorf("loginHandler.ServeHTTP() Allow = %v, want: %v", got, want)
	}
}
