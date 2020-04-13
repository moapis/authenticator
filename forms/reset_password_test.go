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
	"google.golang.org/grpc"
)

const defaultResetPWTmplOut = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>Password reset</title>
</head>
<body>
	<h1>Password reset</h1>
	<form method="post" action="/reset?redirect=http://example.com/foo?hello=world">
		<input type="text" placeholder="Email" name="email" required>
		<button type="submit">Submit</button>
	</form>
</body>
</html>`

func TestForms_resetPWGet(t *testing.T) {
	tests := []struct {
		name     string
		r        *http.Request
		wantCode int
		want     string
	}{
		{
			"Success",
			httptest.NewRequest("GET", "/reset?redirect=http://example.com/foo?hello=world", nil),
			http.StatusOK,
			defaultResetPWTmplOut,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Forms{}
			w := httptest.NewRecorder()

			f.resetPWGet(w, tt.r)

			resp := w.Result()
			body, _ := ioutil.ReadAll(resp.Body)

			if resp.StatusCode != tt.wantCode {
				t.Errorf("Forms.resetPWGet() status = %v, want: %v", resp.StatusCode, tt.wantCode)
			}

			got := string(body)
			if got != tt.want {
				t.Errorf("Forms.resetPWGet() = \n%v\nwant\n%v", got, tt.want)
			}
		})
	}
}

const resetPWFlashOut = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>Password reset</title>
</head>
<body>
	<h1>Password reset</h1>
	<form method="post" action="/reset?redirect=http://example.com/foo?hello=world">
		<input type="text" placeholder="Email" name="email" required>
		<button type="submit">Submit</button>
	</form>
	<p>%s</p>
</body>
</html>`

const resetEmailSent = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>200 OK: Password request link sent</title>
</head>
<body>
	<h1>200 OK</h1>
	<p>Password request link sent</p>
</body>
</html>`

func TestForms_resetPWPost(t *testing.T) {
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
	}{
		{
			"Malformed body",
			httptest.NewRequest("POST", "/reset?redirect=http://example.com/foo?hello=world", strings.NewReader("%sssssssss")),
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(resetPWFlashOut, "error: Malformed form data"),
		},
		{
			"Missing email",
			httptest.NewRequest("POST", "/reset?redirect=http://example.com/foo?hello=world", strings.NewReader("")),
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(resetPWFlashOut, "error: Missing form data: email"),
		},
		{
			"Success",
			httptest.NewRequest("POST", "/reset?redirect=http://example.com/foo?hello=world", strings.NewReader("email=admin@localhost")),
			ctx,
			http.StatusOK,
			resetEmailSent,
		},
		{
			"Internal server error",
			httptest.NewRequest("POST", "/reset?redirect=http://example.com/foo?hello=world", strings.NewReader("email=admin@localhost")),
			ectx,
			http.StatusInternalServerError,
			fmt.Sprintf(resetPWFlashOut, "error: Internal server error"),
		},
		{
			"Internal server error",
			httptest.NewRequest("POST", "/reset?redirect=http://example.com/foo?hello=world", strings.NewReader("email=nobody@localhost")),
			ctx,
			http.StatusUnauthorized,
			fmt.Sprintf(resetPWFlashOut, "error: email not found"),
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

			f.resetPWPost(w, r)

			resp := w.Result()
			body, _ := ioutil.ReadAll(resp.Body)

			if resp.StatusCode != tt.wantCode {
				t.Errorf("Forms.setPWPost() status = %v, want: %v", resp.StatusCode, tt.wantCode)
			}

			if got := string(body); got != tt.wantBody {
				t.Errorf("Forms.setPWPost() = \n%v\nwant\n%v", got, tt.wantBody)
			}
		})
	}
}

func TestForms_ResetPWHandler(t *testing.T) {
	f := &Forms{}
	f.ResetPWHandler()
}

func Test_resetPWHandler_ServeHTTP(t *testing.T) {
	h := resetPWHandler{Forms: &Forms{}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/reset?redirect=http://example.com/foo?hello=world", nil)

	h.ServeHTTP(w, r)

	resp := w.Result()
	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("resetPWHandler.ServeHTTP() GET status = %v, want: %v", resp.StatusCode, http.StatusOK)
	}

	if got := string(body); got != defaultResetPWTmplOut {
		t.Errorf("resetPWHandler.ServeHTTP() GET = \n%v\nwant\n%v", got, defaultSetPWTmplOut)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/reset?redirect=http://example.com/foo?hello=world", strings.NewReader(""))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	h.ServeHTTP(w, r)

	resp = w.Result()
	body, _ = ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("resetPWHandler.ServeHTTP() POST status = %v, want: %v", resp.StatusCode, http.StatusBadRequest)
	}

	want := fmt.Sprintf(resetPWFlashOut, "error: Missing form data: email")
	if got := string(body); got != want {
		t.Errorf("resetPWHandler.ServeHTTP() POST = \n%v\nwant\n%v", got, want)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest("PUT", "/reset?redirect=http://example.com/foo?hello=world", strings.NewReader(""))

	h.ServeHTTP(w, r)

	resp = w.Result()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("resetPWHandler.ServeHTTP() POP status = %v, want: %v", resp.StatusCode, http.StatusMethodNotAllowed)
	}

	want = "GET POST"
	if got := resp.Header.Get("Allow"); !strings.HasPrefix(got, want) {
		t.Errorf("resetPWHandler.ServeHTTP() Allow = %v, want: %v", got, want)
	}
}
