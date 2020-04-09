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

func TestLogin_loginGet(t *testing.T) {
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
			badRequestOut,
		},
		{
			"Success",
			httptest.NewRequest("GET", "/login?redirect=http://example.com/foo?hello=world", nil),
			http.StatusOK,
			defaultTmplOut,
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
				t.Errorf("Login.formHandler() status = %v, want: %v", resp.StatusCode, tt.wantCode)
			}

			got := string(body)
			if got != tt.want {
				t.Errorf("Login.formHandler() = \n%v\nwant\n%v", got, tt.want)
			}
		})
	}
}

func TestLogin_doRedirect(t *testing.T) {
	f := &Forms{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/login?redirect=http://example.com/foo?hello=world", nil)
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	u, err := url.Parse("http://example.com/foo?hello=world")
	if err != nil {
		t.Fatal(err)
	}

	f.doRedirect(w, r, u, "spanac")

	resp := w.Result()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Login.formHandler() status = %v, want: %v", resp.StatusCode, http.StatusSeeOther)
	}

	want := "http://example.com/foo?hello=world&jwt=spanac"
	if got := resp.Header.Get("Location"); got != want {
		t.Errorf("Login.formHandler() Location = %v, want: %v", got, want)
	}
}

func TestLogin_loginPost(t *testing.T) {
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
			fmt.Sprintf(defaultTmplFlash, "error: Malformed form data"),
			"",
		},
		{
			"Missing redirect",
			httptest.NewRequest("POST", "/login", strings.NewReader("email=admin%40localhost&password=admin")),
			ctx,
			http.StatusBadRequest,
			badRequestOut,
			"",
		},
		{
			"No body",
			httptest.NewRequest("POST", "/login?redirect=http://example.com/foo?hello=world", nil),
			ctx,
			http.StatusBadRequest,
			fmt.Sprintf(defaultTmplFlash, "error: Missing form data: Email and Password"),
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
			fmt.Sprintf(defaultTmplFlash, "error: Internal server error"),
			"",
		},
		{
			"Wrong email or password",
			httptest.NewRequest("POST", "/login?redirect=http://example.com/foo?hello=world", strings.NewReader("email=admin%40localhost&password=wrong")),
			ctx,
			http.StatusUnauthorized,
			fmt.Sprintf(defaultTmplFlash, "error: Wrong email or password"),
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
				t.Errorf("Login.postHandler() status = %v, want: %v", resp.StatusCode, tt.wantCode)
			}

			if got := string(body); got != tt.wantBody {
				t.Errorf("Login.postHandler() = \n%v\nwant\n%v", got, tt.wantBody)
			}

			if got := resp.Header.Get("Location"); !strings.HasPrefix(got, tt.wantLoc) {
				t.Errorf("Login.postHandler() Location = %v, want: %v", got, tt.wantLoc)
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
		t.Errorf("Login.ServeHTTP() GET status = %v, want: %v", resp.StatusCode, http.StatusOK)
	}

	if got := string(body); got != defaultTmplOut {
		t.Errorf("Login.ServeHTTP() GET = \n%v\nwant\n%v", got, defaultTmplOut)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/login?redirect=http://example.com/foo?hello=world", strings.NewReader("email=admin%40localhost&password=admin"))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	h.ServeHTTP(w, r)

	resp = w.Result()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Login.ServeHTTP() POST status = %v, want: %v", resp.StatusCode, http.StatusSeeOther)
	}

	want := "http://example.com/foo?hello=world&jwt="
	if got := resp.Header.Get("Location"); !strings.HasPrefix(got, want) {
		t.Errorf("Login.ServeHTTP() Location = %v, want: %v", got, want)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest("PUT", "/login?redirect=http://example.com/foo?hello=world", nil)

	h.ServeHTTP(w, r)

	resp = w.Result()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Login.ServeHTTP() POP status = %v, want: %v", resp.StatusCode, http.StatusMethodNotAllowed)
	}

	want = "GET POST"
	if got := resp.Header.Get("Allow"); !strings.HasPrefix(got, want) {
		t.Errorf("Login.ServeHTTP() Allow = %v, want: %v", got, want)
	}
}
