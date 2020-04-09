package forms

import (
	"bytes"
	"html/template"
	"net/http"
	"net/url"
	"sync"

	auth "github.com/moapis/authenticator"
	"github.com/moapis/ehtml"
	clog "github.com/usrpro/clog15"
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

// FormData is passed to the form templates
type FormData struct {
	Flash     *Flash
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
	LoginTmpl TemplateName = "login"
	// ResetTmpl TemplateName = "reset"
	// SetTmpl   TemplateName = "set"
)

var defaultTmpl = map[TemplateName]*template.Template{
	LoginTmpl: template.Must(template.New("login").Parse(DefaultLoginTmpl)),
}

// Forms implements http.Forms.
// A GET request serves the login form.
// A POST request processes user login.
type Forms struct {
	// Tmpl holds the login form template.
	// If nil a simple placholder is used.
	Tmpl   *template.Template
	EP     ehtml.Pages
	Client auth.AuthenticatorClient

	// Data can be set and will be available in all templates.
	Data interface{}
}

func (f *Forms) template(tn TemplateName) *template.Template {
	if f.Tmpl != nil {
		if tmpl := f.Tmpl.Lookup(string(tn)); tmpl != nil {
			return tmpl
		}
	}

	return defaultTmpl[tn]
}

func (f *Forms) renderForm(w http.ResponseWriter, r *http.Request, tn TemplateName, flash *Flash, status ...int) {
	buf := resPool.Get()
	defer resPool.Put(buf)

	data := &FormData{
		Flash:     flash,
		SubmitURL: r.URL.String(),
		Data:      f.Data,
	}

	ctx := clog.AddArgs(r.Context(), "method", "renderForm", "data", data)

	if err := f.template(tn).Execute(buf, data); err != nil {
		clog.Error(ctx, "Template execution", "err", err)
		if err := f.EP.Render(w, r, http.StatusInternalServerError, "Template execution error", f.Data); err != nil {
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

// RedirectKey for redirect URL in request Query.
// Upon successfull authentication, the client is redirected to the URI under this key.
// Login request: https://example.com/login?redirect=https://secured.com/admin?key=value
// Will redirect to: https://secured.com/admin?key=value&jwt=xxxxxxxxxxx
var RedirectKey = "redirect"

func (f *Forms) getRedirect(r *http.Request) (u *url.URL, err error) {
	values := r.URL.Query()
	ctx := clog.AddArgs(r.Context(), "method", "getRedirect", "url_values", values)

	if red := values.Get(RedirectKey); red != "" {
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
