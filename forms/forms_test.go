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

	"github.com/moapis/ehtml"
)

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

const defaultTmplOut = `<!DOCTYPE html>
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
</body>
</html>`

func TestForms_template(t *testing.T) {
	data := &FormData{
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
			defaultTmplOut,
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
				t.Errorf("Login.template() = \n%v\nwant\n%v", got, tt.want)
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

const defaultTmplFlash = `<!DOCTYPE html>
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
			defaultTmplOut,
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
			fmt.Sprintf(defaultTmplFlash, "error: missing password"),
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

			f.renderForm(w, req, LoginTmpl, tt.args.flash, tt.args.status)

			resp := w.Result()
			body, _ := ioutil.ReadAll(resp.Body)

			if resp.StatusCode != tt.wantCode {
				t.Errorf("Login.Render() status = %v, want: %v", resp.StatusCode, tt.wantCode)
			}

			got := string(body)
			if got != tt.want {
				t.Errorf("Login.Render() = \n%v\nwant\n%v", got, tt.want)
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

	h.renderForm(w, r, LoginTmpl, nil)
}

const badRequestOut = `<!DOCTYPE html>
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
				t.Errorf("Login.getRedirect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotU, tt.wantU) {
				t.Errorf("Login.getRedirect() URL = %v, want %v", gotU, tt.wantU)
			}

		})
	}
}
