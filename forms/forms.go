package forms

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sync"

	auth "github.com/moapis/authenticator"
	"github.com/moapis/ehtml"
	clog "github.com/usrpro/clog15"
)

const (
	// AllowedMethods for the handlers of this package
	AllowedMethods = http.MethodGet + " " + http.MethodPost
)

// Titles passed to templates
var (
	LoginTitle   = "Please login"
	ResetPWTitle = "Reset password"
	SetPWTitle   = "Set new password"
)

// Flash message targets the user with info, warning or error message
type Flash struct {
	Lvl FlashLvl
	Msg string
}

// FlashLvl indicates the severity of Flash
type FlashLvl string

// Predefined Flash levels
const (
	InfoFlashLvl FlashLvl = "info"
	WarnFlashLvl FlashLvl = "warning"
	ErrFlashLvl  FlashLvl = "error"
)

// Navigation links to other forms
type Navigation struct {
	Login, Reset, Set template.URL
}

func navigation(r *http.Request, p *Paths) Navigation {
	if r.URL.RawQuery == "" {
		return Navigation{
			Login: template.URL(p.login()),
			Reset: template.URL(p.resetPW()),
			Set:   template.URL(p.setPW()),
		}
	}

	return Navigation{
		Login: template.URL(fmt.Sprintf("%s?%s", p.login(), r.URL.RawQuery)),
		Reset: template.URL(fmt.Sprintf("%s?%s", p.resetPW(), r.URL.RawQuery)),
		Set:   template.URL(fmt.Sprintf("%s?%s", p.setPW(), r.URL.RawQuery)),
	}
}

// FormData is passed to the form templates
type FormData struct {
	Title     string
	Flash     *Flash
	Nav       Navigation
	SubmitURL string
	Data      interface{} // As set on the Forms object
}

type bufferPool struct {
	p sync.Pool
}

func (b *bufferPool) Get() *bytes.Buffer {
	buf, ok := b.p.Get().(*bytes.Buffer)
	if ok {
		return buf
	}
	return new(bytes.Buffer)
}

func (b *bufferPool) Put(buf *bytes.Buffer) {
	buf.Reset()
	b.p.Put(buf)
}

// resPool recycles buffers for template execution output
var resPool bufferPool

// TemplateName is used to predefine template naming requirements.
type TemplateName string

// Predefined Template Names.
const (
	LoginTmpl   TemplateName = "login"
	ResetPWTmpl TemplateName = "reset"
	SetPWTmpl   TemplateName = "setpw"
)

var defaultTmpl = map[TemplateName]*template.Template{
	LoginTmpl:   template.Must(template.New(string(LoginTmpl)).Parse(DefaultLoginTmpl)),
	ResetPWTmpl: template.Must(template.New(string(ResetPWTmpl)).Parse(DefaultResetPWTmpl)),
	SetPWTmpl:   template.Must(template.New(string(SetPWTmpl)).Parse(DefaultSetPWTmpl)),
}

// Forms implements http.Forms.
// A GET request serves the login form.
// A POST request processes user login.
type Forms struct {
	// Tmpl holds the login form template.
	// If nil a simple placholder is used.
	Tmpl *template.Template
	EP   ehtml.Pages
	// Data will be available in all templates.
	Data interface{}

	Client auth.AuthenticatorClient
	Paths  *Paths
}

func (f *Forms) template(tn TemplateName) *template.Template {
	if f.Tmpl != nil {
		if tmpl := f.Tmpl.Lookup(string(tn)); tmpl != nil {
			return tmpl
		}
	}

	return defaultTmpl[tn]
}

func (f *Forms) renderForm(w http.ResponseWriter, r *http.Request, tn TemplateName, title string, flash *Flash, status ...int) {
	buf := resPool.Get()
	defer resPool.Put(buf)

	data := &FormData{
		Title:     title,
		Flash:     flash,
		Nav:       navigation(r, f.Paths),
		SubmitURL: r.URL.String(),
		Data:      f.Data,
	}

	ctx := clog.AddArgs(r.Context(), "method", "renderForm", "data", data)

	if err := f.template(tn).Execute(buf, data); err != nil {
		clog.Error(ctx, "Template execution", "err", err)
		if err := f.EP.Render(w, &ehtml.Data{Req: r, Code: http.StatusInternalServerError, Msg: "Template execution error"}); err != nil {
			clog.Error(ctx, "During handling error", "err", err)
		}
		return
	}

	if len(status) > 0 {
		w.WriteHeader(status[0])
	}

	if _, err := buf.WriteTo(w); err != nil {
		clog.Warn(ctx, "Write to client", "err", err)
	}
}

var ()

func (f *Forms) getRedirect(r *http.Request) (u *url.URL, err error) {
	values := r.URL.Query()
	ctx := clog.AddArgs(r.Context(), "method", "getRedirect", "url_values", values)

	if red := values.Get(f.Paths.redirectKey()); red != "" {
		if u, err = url.Parse(red); err == nil {
			return u, nil
		}
		clog.Warn(ctx, redirectInvalid, "err", err, "red", red)
		err = errRedirectInvalid
	} else {
		clog.Warn(ctx, redirectMissing)
		err = errRedirectMissing
	}

	return
}

// Paths are used for generating Redirect responses,
// e-mailed links and route generation.
// All paths must be absolute, with leading slash.
type Paths struct {
	// Public address of the server.
	ServerAddress string `json:"server_address,omitempty"`
	SetPW         string `json:"set_pw,omitempty"`
	ResetPW       string `json:"reset_pw,omitempty"`
	Login         string `json:"login,omitempty"`
	// RedirectKey for redirect URL in request Query.
	// Upon successfull authentication, the client is redirected to the URL under this key.
	// Login request: https://example.com/login?redirect=https://secured.com/admin?key=value
	// Will redirect to: https://secured.com/admin?key=value&jwt=xxxxxxxxxxx
	RedirectKey string `json:"redirect_key,omitempty"`
	// TokenKey is under which key the JSON web token will be embedded in the URL query,
	// when executing the redirect.
	TokenKey string `json:"token_key,omitempty"`
}

// Defaults when Forms.Paths is nil, or field is empty.
const (
	DefaultServerAddress = "http://localhost:1234"
	DefaultSetPWPath     = "/set-password"
	DefaultResetPWPath   = "/reset-password"
	DefaultLoginPath     = "/login"
	DefaultRedirectKey   = "redirect"
	DefaultTokenKey      = "jwt"
)

func (p *Paths) server() string {
	if p == nil || p.ServerAddress == "" {
		return DefaultServerAddress
	}
	return p.ServerAddress
}

func (p *Paths) setPW() string {
	if p == nil || p.SetPW == "" {
		return DefaultSetPWPath
	}
	return p.SetPW
}

func (p *Paths) resetPW() string {
	if p == nil || p.ResetPW == "" {
		return DefaultResetPWPath
	}
	return p.ResetPW
}

func (p *Paths) login() string {
	if p == nil || p.Login == "" {
		return DefaultLoginPath
	}
	return p.Login
}

func (p *Paths) redirectKey() string {
	if p == nil || p.RedirectKey == "" {
		return DefaultRedirectKey
	}
	return p.RedirectKey
}

func (p *Paths) tokenKey() string {
	if p == nil || p.TokenKey == "" {
		return DefaultTokenKey
	}
	return p.TokenKey
}

// callbackURL is generated from the incomming request Query and the new desired path.
func (p *Paths) callbackURL(values url.Values, path string) *auth.CallBackUrl {
	params := make(map[string]*auth.StringSlice, len(values))

	for k, v := range values {
		params[k] = &auth.StringSlice{Slice: v}
	}

	return &auth.CallBackUrl{
		BaseUrl:  fmt.Sprint(p.server(), path),
		TokenKey: p.tokenKey(),
		Params:   params,
	}
}
