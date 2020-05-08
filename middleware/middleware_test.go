// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package middleware

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/moapis/authenticator"
	"github.com/moapis/authenticator/verify"
	"google.golang.org/grpc"
)

func Test_getJwt(t *testing.T) {
	withCookie := httptest.NewRequest("GET", "http://example.com/secret", nil)
	withCookie.AddCookie(&http.Cookie{
		Name:  "jwt",
		Value: "foobar",
	})

	tests := []struct {
		name          string
		r             *http.Request
		wantTkn       string
		wantNewCookie bool
		wantErr       bool
	}{
		{
			"Token in url",
			httptest.NewRequest("GET", "http://example.com/secret?jwt=spanac", nil),
			"spanac",
			true,
			false,
		},
		{
			"No cookie, no url",
			httptest.NewRequest("GET", "http://example.com/secret", nil),
			"",
			false,
			true,
		},
		{
			"With cookie",
			withCookie,
			"foobar",
			false,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTkn, gotNewCookie, err := getJwt(tt.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("getJwt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotTkn != tt.wantTkn {
				t.Errorf("getJwt() gotTkn = %v, want %v", gotTkn, tt.wantTkn)
			}
			if gotNewCookie != tt.wantNewCookie {
				t.Errorf("getJwt() gotNewCookie = %v, want %v", gotNewCookie, tt.wantNewCookie)
			}
		})
	}
}

func TestClient_loginRedirect(t *testing.T) {
	client := Client{
		ServerAddress: "http://example.com",
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		client.loginRedirect(context.Background(), w, r, nil)
	}

	type test struct {
		name string
		uri  string
		want string
	}
	tests := []test{
		{
			name: "clean uri",
			uri:  "http://example.com/foo",
			want: `<a href="/login?redirect=http://example.com/foo">See Other</a>.`,
		},
		{
			name: "uri with jwt",
			uri:  "http://example.com/foo?jwt=spanac",
			want: `<a href="/login?redirect=http://example.com/foo">See Other</a>.`,
		},
		{
			name: "uri with jwt and other",
			uri:  "http://example.com/foo?jwt=spanac&foo=bar",
			want: `<a href="/login?redirect=http://example.com/foo?foo=bar">See Other</a>.`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.uri, nil)
			w := httptest.NewRecorder()
			handler(w, req)

			resp := w.Result()
			body, _ := ioutil.ReadAll(resp.Body)

			if resp.StatusCode != http.StatusSeeOther {
				t.Errorf("Client.loginRedirect() statuscode: %v, want: %v", resp.StatusCode, http.StatusSeeOther)
			}

			got := strings.Trim(string(body), "\n\r \t")

			if got != tt.want {
				t.Errorf("Client.loginRedirect()\nbody: %v\nwant: %v", got, tt.want)
			}
		})
	}
}

var (
	testClient *Client
	validTkn   string
)

const testUser = "admin@localhost"

func init() {
	var cc *grpc.ClientConn
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for cc == nil {
		err := ctx.Err()
		if err != nil {
			log.Fatalf("%v; giving up", err)
		}

		log.Println("(re-)trying gRPC dial")

		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)

		if cc, err = grpc.DialContext(ctx, "127.0.0.1:8765", grpc.WithBlock(), grpc.WithInsecure()); err != nil {
			log.Println(err)
		}

		cancel()
	}

	testClient = &Client{
		Verificator: &verify.Verificator{
			Client:    authenticator.NewAuthenticatorClient(cc),
			Audiences: []string{"authenticator"},
		},
		ServerAddress: "http://example.com",
	}

	ar, err := testClient.Verificator.Client.AuthenticatePwUser(
		ctx, &authenticator.UserPassword{
			Email:    testUser,
			Password: "admin",
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	validTkn = ar.GetJwt()
}

func TestClient_refreshToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got, err := testClient.refreshToken(ctx, validTkn)
	if err != nil {
		t.Fatal(err)
	}

	if got == validTkn {
		t.Errorf("Client.refreshToken() token %s not refreshed. Got: %s", validTkn, got)
	}

	cancel()
	if _, err = testClient.refreshToken(ctx, validTkn); err == nil {
		t.Errorf("Client.refreshToken() err: %v, Want error", err)
	}

}

func TestClient_newCookie(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		testClient.newCookie(w, r, "spanac", time.Unix(123, 456))
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	resp := w.Result()

	want := &http.Cookie{
		Name:    "jwt",
		Value:   "spanac",
		Path:    "/",
		Expires: time.Unix(123, 456),
	}

	var got *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "jwt" {
			got = c
		}
	}
	if got.String() != want.String() {
		t.Errorf("Client.newCookie() resp:\n%v\nwant\n%v", got, want)
	}
}

func TestClient_isGroupMember(t *testing.T) {
	type fields struct {
		Groups []string
	}
	tests := []struct {
		name    string
		fields  fields
		set     map[string]interface{}
		wantErr bool
	}{
		{
			"No groups, nil set",
			fields{},
			nil,
			false,
		},
		{
			"nil set",
			fields{
				Groups: []string{"foo", "bar"},
			},
			nil,
			true,
		},
		{
			"found",
			fields{
				Groups: []string{"foo", "bar"},
			},
			map[string]interface{}{
				"groups": []interface{}{"bar"},
			},
			false,
		},
		{
			"wrong type",
			fields{
				Groups: []string{"foo", "bar"},
			},
			map[string]interface{}{
				"groups": []interface{}{1, "foo"},
			},
			false,
		},
		{
			"wrong group",
			fields{
				Groups: []string{"foo", "bar"},
			},
			map[string]interface{}{
				"groups": []interface{}{"spanac"},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				Groups: tt.fields.Groups,
			}
			if err := c.isGroupMember(tt.set); (err != nil) != tt.wantErr {
				t.Errorf("Client.isGroupMember() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_Middleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(ClaimsKey).(Claims)
		if !ok {
			t.Errorf("Claims in context %v type %T", r.Context().Value(ClaimsKey), r.Context().Value(ClaimsKey))
		}

		if claims.Subject != testUser {
			t.Errorf("Claims.subject = %s, want: %s", claims.Subject, testUser)
			t.Log(*claims.Claims)
		}

		w.Write([]byte("OK"))
	})

	ectx, cancel := context.WithCancel(context.Background())
	cancel()

	refrClient := *testClient
	refrClient.RefreshWithin = 4000 * time.Hour

	groupClient := *testClient
	groupClient.Groups = []string{"foobar"}

	cookReq := httptest.NewRequest("GET", "http://example.com/foo", nil)
	cookReq.AddCookie(&http.Cookie{
		Name:  "jwt",
		Value: validTkn,
	})

	type want struct {
		status int
		body   string
	}
	tests := []struct {
		name   string
		client *Client
		r      *http.Request
		want   want
	}{
		{
			"No jwt",
			testClient,
			httptest.NewRequest("GET", "http://example.com/foo", nil),
			want{
				http.StatusSeeOther,
				`<a href="/login?redirect=http://example.com/foo">See Other</a>.`,
			},
		},
		{
			"Internal server error",
			testClient,
			httptest.NewRequest("GET", "http://example.com/foo?jwt="+validTkn, nil).WithContext(ectx),
			want{
				http.StatusInternalServerError,
				intServErr,
			},
		},
		{
			"Invalid token",
			testClient,
			httptest.NewRequest("GET", "http://example.com/foo?jwt=spanac", nil),
			want{
				http.StatusSeeOther,
				`<a href="/login?redirect=http://example.com/foo">See Other</a>.`,
			},
		},
		{
			"Valid token in URL",
			testClient,
			httptest.NewRequest("GET", "http://example.com/foo?jwt="+validTkn, nil),
			want{
				http.StatusOK,
				"OK",
			},
		},
		{
			"Refresh token in URL",
			&refrClient,
			httptest.NewRequest("GET", "http://example.com/foo?jwt="+validTkn, nil),
			want{
				http.StatusOK,
				"OK",
			},
		},
		{
			"Valid token in cookie",
			testClient,
			cookReq,
			want{
				http.StatusOK,
				"OK",
			},
		},
		{
			"Valid token in URL, wrong group",
			&groupClient,
			httptest.NewRequest("GET", "http://example.com/foo?jwt="+validTkn, nil),
			want{
				http.StatusSeeOther,
				`<a href="/login?redirect=http://example.com/foo">See Other</a>.`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tt.client.Middleware(next).ServeHTTP(w, tt.r)

			res := w.Result()
			if res.StatusCode != tt.want.status {
				t.Errorf("Client.Middleware() status: %d, want: %d", res.StatusCode, tt.want.status)
			}
			body, _ := ioutil.ReadAll(res.Body)
			got := strings.Trim(string(body), "\n\r\t ")
			if got != tt.want.body {
				t.Errorf("Client.Middleware() status:\n%s\nwant\n%s", got, tt.want.body)
			}
		})
	}
}
