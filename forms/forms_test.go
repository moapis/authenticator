package forms

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	auth "github.com/moapis/authenticator"
	"github.com/moapis/ehtml"
)

func Test_navigation(t *testing.T) {
	const query = "?redirect=http://example.com/foo?hello=world"

	tests := []struct {
		name string
		r    *http.Request
		want Navigation
	}{
		{
			"Without query vars",
			httptest.NewRequest("GET", "/login", nil),
			Navigation{
				Login: DefaultLoginPath,
				Reset: DefaultResetPWPath,
				Set:   DefaultSetPWPath,
			},
		},
		{
			"With query vars",
			httptest.NewRequest("GET", "/login"+query, nil),
			Navigation{
				Login: DefaultLoginPath + query,
				Reset: DefaultResetPWPath + query,
				Set:   DefaultSetPWPath + query,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := navigation(tt.r, &Paths{}); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("navigation() =\n%v\nwant\n%v", got, tt.want)
			}
		})
	}
}

func Test_bufferPool(t *testing.T) {
	buf := resPool.Get()
	if buf == nil {
		t.Fatalf("resPool.Get() buf: %v", buf)
	}

	resPool.Put(buf)

	buf = resPool.Get()
	if buf == nil {
		t.Fatalf("resPool.Get() buf: %v", buf)
	}
}

func TestForms_template(t *testing.T) {
	data := &FormData{
		Title:     LoginTitle,
		Nav:       navigation(httptest.NewRequest("GET", "/login?redirect=http://example.com/foo?hello=world", nil), &Paths{}),
		SubmitURL: "/login?redirect=http://example.com/foo?hello=world",
	}

	tests := []struct {
		name string
		tmpl *template.Template
		want string
	}{
		{
			"Default template",
			nil,
			defaultLoginTmplOut,
		},
		{
			"Custom template",
			template.Must(template.New("login").Parse(`{{ define "login" }}Foo bar{{ end }}`)),
			"Foo bar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Forms{
				Tmpl: tt.tmpl,
			}
			var buf bytes.Buffer

			if err := f.template(LoginTmpl).Execute(&buf, data); err != nil {
				t.Fatal(err)
			}

			if got := buf.String(); got != tt.want {
				t.Errorf("Forms.template() = \n%v\nwant\n%v", got, tt.want)
			}
		})
	}
}

const errPageOut = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>500 Internal Server Error: Template execution error</title>
</head>
<body>
	<h1>500 Internal Server Error</h1>
	<p>Template execution error</p>
</body>
</html>`

var (
	errTmpl   = template.Must(template.New("login").Parse(`{{ define "login" }}{{ .Missing }}{{ end }}`))
	epErrTmpl = template.Must(template.New("error").Parse(`{{ define "error" }}{{ .Missing }}{{ end }}`))
)

func TestForms_renderForm(t *testing.T) {
	type fields struct {
		Tmpl *template.Template
		Data interface{}
		EP   ehtml.Pages
	}
	type args struct {
		flash  *Flash
		status int
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantCode int
		want     string
	}{
		{
			"Default case",
			fields{},
			args{},
			http.StatusOK,
			defaultLoginTmplOut,
		},
		{
			"Template execution error",
			fields{
				Tmpl: errTmpl,
			},
			args{},
			http.StatusInternalServerError,
			errPageOut,
		},
		{
			"Error page error",
			fields{
				Tmpl: errTmpl,
				EP:   ehtml.Pages{Tmpl: epErrTmpl},
			},
			args{},
			http.StatusInternalServerError,
			"500 Internal server error. While handling:\n500 Internal Server Error: Template execution error",
		},
		{
			"With flash and code",
			fields{},
			args{
				&Flash{
					ErrFlashLvl,
					"missing password",
				},
				http.StatusBadRequest,
			},
			http.StatusBadRequest,
			fmt.Sprintf(loginFlashOut, "error: missing password"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Forms{
				Tmpl: tt.fields.Tmpl,
				Data: tt.fields.Data,
				EP:   tt.fields.EP,
			}

			req := httptest.NewRequest("GET", "/login?redirect=http://example.com/foo?hello=world", nil)
			w := httptest.NewRecorder()

			f.renderForm(w, req, LoginTmpl, LoginTitle, tt.args.flash, tt.args.status)

			resp := w.Result()
			body, _ := ioutil.ReadAll(resp.Body)

			if resp.StatusCode != tt.wantCode {
				t.Errorf("Forms.renderForm() status = %v, want: %v", resp.StatusCode, tt.wantCode)
			}

			got := string(body)
			if got != tt.want {
				t.Errorf("Forms.renderForm() = \n%v\nwant\n%v", got, tt.want)
			}
		})
	}
}

type errorWriter struct{}

func (errorWriter) Header() http.Header       { return nil }
func (errorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (errorWriter) WriteHeader(int)           {}

func TestForms_renderForm_writeErr(t *testing.T) {
	h := &Forms{}
	w := errorWriter{}
	r := httptest.NewRequest("GET", "/login?redirect=http://example.com/foo?hello=world", nil)

	h.renderForm(w, r, LoginTmpl, LoginTitle, nil)
}

func TestForms_getRedirect(t *testing.T) {
	wantU, err := url.Parse("http://example.com/foo?hello=world")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		r       *http.Request
		wantU   *url.URL
		wantErr bool
	}{
		{
			"Valid redirect",
			httptest.NewRequest("GET", "/login?redirect=http://example.com/foo?hello=world", nil),
			wantU,
			false,
		},
		{
			"Missing redirect",
			httptest.NewRequest("GET", "/login", nil),
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Forms{}

			gotU, err := f.getRedirect(tt.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("Forms.getRedirect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotU, tt.wantU) {
				t.Errorf("Forms.getRedirect() URL = %v, want %v", gotU, tt.wantU)
			}

		})
	}
}

func TestPaths_callbackURL(t *testing.T) {
	type args struct {
		r    *http.Request
		path string
	}
	tests := []struct {
		name string
		args args
		want *auth.CallBackUrl
	}{
		{
			"No query",
			args{
				httptest.NewRequest("POST", "https://example.com/reset", nil),
				"/setpw",
			},
			&auth.CallBackUrl{
				BaseUrl:  "http://localhost:1234/setpw",
				TokenKey: DefaultTokenKey,
				Params:   map[string]*auth.StringSlice{},
			},
		},
		{
			"with query",
			args{
				httptest.NewRequest("POST", "https://example.com/reset?foo=bar&hello=world", nil),
				"/setpw",
			},
			&auth.CallBackUrl{
				BaseUrl:  "http://localhost:1234/setpw",
				TokenKey: DefaultTokenKey,
				Params: map[string]*auth.StringSlice{
					"foo":   {Slice: []string{"bar"}},
					"hello": {Slice: []string{"world"}},
				},
			},
		},
	}
	for _, tt := range tests {
		var p *Paths
		t.Run(tt.name, func(t *testing.T) {
			if got := p.callbackURL(tt.args.r.URL.Query(), tt.args.path); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CallbackURL() =\n%v\nwant\n%v", got, tt.want)
			}
		})
	}
}

func TestPaths_server(t *testing.T) {
	tests := []struct {
		name string
		p    *Paths
		want string
	}{
		{
			"nil",
			nil,
			DefaultServerAddress,
		},
		{
			"empty",
			&Paths{},
			DefaultServerAddress,
		},
		{
			"Set",
			&Paths{ServerAddress: "http://foobar.com"},
			"http://foobar.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.server(); got != tt.want {
				t.Errorf("Paths.server() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPaths_setpw(t *testing.T) {
	tests := []struct {
		name string
		p    *Paths
		want string
	}{
		{
			"nil",
			nil,
			DefaultSetPWPath,
		},
		{
			"empty",
			&Paths{},
			DefaultSetPWPath,
		},
		{
			"Set",
			&Paths{SetPW: "/foobar"},
			"/foobar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.setPW(); got != tt.want {
				t.Errorf("Paths.server() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPaths_resetpw(t *testing.T) {
	tests := []struct {
		name string
		p    *Paths
		want string
	}{
		{
			"nil",
			nil,
			DefaultResetPWPath,
		},
		{
			"empty",
			&Paths{},
			DefaultResetPWPath,
		},
		{
			"Set",
			&Paths{ResetPW: "/foobar"},
			"/foobar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.resetPW(); got != tt.want {
				t.Errorf("Paths.server() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPaths_login(t *testing.T) {
	tests := []struct {
		name string
		p    *Paths
		want string
	}{
		{
			"nil",
			nil,
			DefaultLoginPath,
		},
		{
			"empty",
			&Paths{},
			DefaultLoginPath,
		},
		{
			"Set",
			&Paths{Login: "/foobar"},
			"/foobar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.login(); got != tt.want {
				t.Errorf("Paths.server() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPaths_redirectKey(t *testing.T) {
	tests := []struct {
		name string
		p    *Paths
		want string
	}{
		{
			"nil",
			nil,
			DefaultRedirectKey,
		},
		{
			"empty",
			&Paths{},
			DefaultRedirectKey,
		},
		{
			"Set",
			&Paths{RedirectKey: "foo"},
			"foo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.redirectKey(); got != tt.want {
				t.Errorf("Paths.server() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPaths_tokenKey(t *testing.T) {
	tests := []struct {
		name string
		p    *Paths
		want string
	}{
		{
			"nil",
			nil,
			DefaultTokenKey,
		},
		{
			"empty",
			&Paths{},
			DefaultTokenKey,
		},
		{
			"Set",
			&Paths{TokenKey: "foo"},
			"foo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.tokenKey(); got != tt.want {
				t.Errorf("Paths.server() = %v, want %v", got, tt.want)
			}
		})
	}
}
