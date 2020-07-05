package forms

import (
	"context"
	"net/http"
	"time"

	auth "github.com/moapis/authenticator"
	"github.com/moapis/ehtml"
	clog "github.com/usrpro/clog15"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DefaultResetPWTmpl is a placeholder template for `Login`
const DefaultResetPWTmpl = `{{ define "reset" -}}
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>Password reset</title>
</head>
<body>
	<h1>Password reset</h1>
	<form method="post" action="{{ .SubmitURL }}">
		<input type="text" placeholder="Email" name="email" required>
		<button type="submit">Submit</button>
	</form>
	{{- if .Flash }}
	<p>{{ .Flash.Lvl }}: {{ .Flash.Msg }}</p>
	{{- end }}
</body>
</html>
{{- end -}}
`

func (f *Forms) resetPWGet(w http.ResponseWriter, r *http.Request) {
	f.renderForm(w, r, ResetPWTmpl, ResetPWTitle, nil)
}

func (f *Forms) resetPWPost(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	ctx = clog.AddArgs(ctx, "method", "resetPWPost")

	if err := r.ParseForm(); err != nil {
		clog.Warn(ctx, "Parseform", "err", err)
		fl := &Flash{ErrFlashLvl, "Malformed form data"}
		f.renderForm(w, r, ResetPWTmpl, ResetPWTitle, fl, http.StatusBadRequest)
		return
	}

	email := r.PostForm.Get("email")
	if email == "" {
		clog.Warn(ctx, "Missing email in form")
		fl := &Flash{ErrFlashLvl, "Missing form data: email"}
		f.renderForm(w, r, ResetPWTmpl, ResetPWTitle, fl, http.StatusBadRequest)
		return
	}

	_, err := f.Client.ResetUserPW(ctx, &auth.UserEmail{
		Email: email,
		Url:   f.Paths.callbackURL(r.URL.Query(), f.Paths.setPW()),
	})
	if err == nil {
		if err = f.EP.Render(w, &ehtml.Data{Req: r, Code: http.StatusOK, Msg: "Password request link sent"}); err != nil {
			clog.Error(ctx, "EP.Render", "err", err)
		}
		return
	}

	var (
		flash *Flash
		sc    int
	)

	s, ok := status.FromError(err)
	if !ok || s.Code() != codes.NotFound {
		clog.Error(ctx, "ResetUserPW gRPC call", "err", err)
		flash, sc = &Flash{ErrFlashLvl, "Internal server error"}, http.StatusInternalServerError
	} else {
		clog.Info(ctx, "ResetUserPW gRPC call", "err", err)
		flash, sc = &Flash{ErrFlashLvl, "email not found"}, http.StatusUnauthorized
	}

	f.renderForm(w, r, ResetPWTmpl, ResetPWTitle, flash, sc)
}

// ResetPWHandler returns the handler taking care
// of password setting, using a reset token.
// GET serves the "reset" form template.
// POST forwards the request over gPRC,
// which sends and an e-mail with a reset
// link to the submitted e-mail address, if it is registered.
func (f *Forms) ResetPWHandler() http.Handler {
	return &resetPWHandler{f}
}

type resetPWHandler struct {
	*Forms
}

func (h *resetPWHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(clog.AddArgs(r.Context(), "pkg", "authenticator.forms", "handler", "SetPW"))

	switch r.Method {
	case http.MethodGet:
		h.resetPWGet(w, r)
	case http.MethodPost:
		h.resetPWPost(w, r)
	default:
		w.Header().Add("Allow", AllowedMethods)
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
