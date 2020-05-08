package forms

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.com/moapis/authenticator"
	"github.com/moapis/ehtml"
	clog "github.com/usrpro/clog15"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DefaultLoginTmpl is a placeholder template for `Login`
const DefaultLoginTmpl = `{{ define "login" -}}
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>{{ .Title }}</title>
</head>
<body>
	<h1>{{ .Title }}</h1>
	<form method="post" action="{{ .SubmitURL }}">
		<input type="email" placeholder="Email" name="email" required>
		<input type="password" placeholder="Password" name="password" required>
		<button type="submit">Sign In</button>
	</form>
	{{- if .Flash }}
	<p>{{ .Flash.Lvl }}: {{ .Flash.Msg }}</p>
	{{- end }}
	<p><a href="{{ .Nav.Reset }}">Password reset</a></p>
</body>
</html>
{{- end -}}
`

const (
	redirectMissing = "Missing redirect in URL"
	redirectInvalid = "Invalid redirect URL"
)

var (
	errRedirectMissing = errors.New(redirectMissing)
	errRedirectInvalid = errors.New(redirectInvalid)
)

func (f *Forms) loginGet(w http.ResponseWriter, r *http.Request) {
	ctx := clog.AddArgs(r.Context(), "method", "loginGet")

	if _, err := f.getRedirect(r); err != nil {
		if err := f.EP.Render(w, &ehtml.Data{Req: r, Code: http.StatusBadRequest, Msg: err.Error()}); err != nil {
			clog.Error(ctx, "During handling error", "err", err)
		}
		return
	}

	f.renderForm(w, r, LoginTmpl, LoginTitle, nil)
}

func (*Forms) loginRedirect(w http.ResponseWriter, r *http.Request, u *url.URL, tkn string) {
	q := u.Query()
	q.Set("jwt", tkn)

	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func (f *Forms) loginPost(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	ctx = clog.AddArgs(ctx, "method", "postHandler")

	if err := r.ParseForm(); err != nil {
		clog.Warn(ctx, "Parseform", "err", err)
		fl := &Flash{ErrFlashLvl, "Malformed form data"}
		f.renderForm(w, r, LoginTmpl, LoginTitle, fl, http.StatusBadRequest)
		return
	}

	rURL, err := f.getRedirect(r)
	if err != nil {
		if err := f.EP.Render(w, &ehtml.Data{Req: r, Code: http.StatusBadRequest, Msg: err.Error()}); err != nil {
			clog.Error(ctx, "During handling error", "err", err)
		}
		return
	}

	var missing []string

	email, password := r.PostForm.Get("email"), r.PostForm.Get("password")
	if email == "" {
		missing = append(missing, "Email")
	}
	if password == "" {
		missing = append(missing, "Password")
	}

	if len(missing) > 0 {
		clog.Warn(ctx, "Missing form data", "missing", missing)
		fl := &Flash{ErrFlashLvl, fmt.Sprintf("Missing form data: %s", strings.Join(missing, " and "))}
		f.renderForm(w, r, LoginTmpl, LoginTitle, fl, http.StatusBadRequest)
		return
	}

	reply, err := f.Client.AuthenticatePwUser(ctx, &auth.UserPassword{
		Email:    email,
		Password: password,
	})
	if err == nil {
		f.loginRedirect(w, r, rURL, reply.GetJwt())
		return
	}

	var (
		flash *Flash
		sc    int
	)

	s, ok := status.FromError(err)
	if !ok || s.Code() != codes.Unauthenticated {
		clog.Error(ctx, "AuthenticatePwUser gRPC call", "err", err)
		flash, sc = &Flash{ErrFlashLvl, "Internal server error"}, http.StatusInternalServerError
	} else {
		clog.Info(ctx, "AuthenticatePwUser gRPC call", "err", err)
		flash, sc = &Flash{ErrFlashLvl, "Wrong email or password"}, http.StatusUnauthorized
	}

	f.renderForm(w, r, LoginTmpl, LoginTitle, flash, sc)
}

// LoginHander returns the handler taking care of login GET and POST requests.
// GET serves the "login" form template.
// POST checks the user's credentials over gRPC.
func (f *Forms) LoginHander() http.Handler {
	return &loginHandler{f}
}

type loginHandler struct {
	*Forms
}

func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(clog.AddArgs(r.Context(), "pkg", "authenticator.forms", "handler", "Login"))

	switch r.Method {
	case http.MethodGet:
		h.loginGet(w, r)
	case http.MethodPost:
		h.loginPost(w, r)
	default:
		w.Header().Add("Allow", AllowedMethods)
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
