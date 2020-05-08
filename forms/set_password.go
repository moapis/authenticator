package forms

import (
	"context"
	"fmt"
	"net/http"
	"time"

	auth "github.com/moapis/authenticator"
	"github.com/moapis/ehtml"
	clog "github.com/usrpro/clog15"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DefaultSetPWTmpl is a placeholder template for `Login`
const DefaultSetPWTmpl = `{{ define "setpw" -}}
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>Set password</title>
</head>
<body>
	<h1>Set a new password</h1>
	<form method="post" action="{{ .SubmitURL }}">
		<input type="password" placeholder="Password" name="password" required>
		<button type="submit">Submit</button>
	</form>
	{{- if .Flash }}
	<p>{{ .Flash.Lvl }}: {{ .Flash.Msg }}</p>
	{{- end }}
</body>
</html>
{{- end -}}
`

func (f *Forms) setPWGet(w http.ResponseWriter, r *http.Request) {
	ctx := clog.AddArgs(r.Context(), "method", "setPWGet")

	tkn := r.URL.Query().Get("jwt")
	if tkn == "" {
		if err := f.EP.Render(w, &ehtml.Data{Req: r, Code: http.StatusBadRequest, Msg: "Missing token in URL"}); err != nil {
			clog.Error(ctx, "During handling error", "err", err)
		}
		return
	}

	f.renderForm(w, r, SetPWTmpl, SetPWTitle, nil)
}

func (f *Forms) setPWRedirect(w http.ResponseWriter, r *http.Request) {
	ctx := clog.AddArgs(r.Context(), "method", "setPWRedirect")

	rURL, err := f.getRedirect(r)
	if err != nil {
		if err := f.EP.Render(w, &ehtml.Data{Req: r, Code: http.StatusOK,
			Msg: "Password set succesfully. You can now close this window",
		}); err != nil {
			clog.Error(ctx, "During handling error", "err", err)
		}
		return
	}

	http.Redirect(w, r,
		fmt.Sprintf("%s?%s=%s", f.Paths.login(), f.Paths.redirectKey(), rURL),
		http.StatusSeeOther)
}

func (f *Forms) setPWPost(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	ctx = clog.AddArgs(ctx, "method", "setPWPost")

	if err := r.ParseForm(); err != nil {
		clog.Warn(ctx, "Parseform", "err", err)
		fl := &Flash{ErrFlashLvl, "Malformed form data"}
		f.renderForm(w, r, SetPWTmpl, SetPWTitle, fl, http.StatusBadRequest)
		return
	}

	tkn := r.URL.Query().Get("jwt")
	if tkn == "" {
		if err := f.EP.Render(w, &ehtml.Data{Req: r, Code: http.StatusBadRequest, Msg: "Missing token in URL"}); err != nil {
			clog.Error(ctx, "During handling error", "err", err)
		}
		return
	}

	npw := r.PostForm.Get("password")
	if npw == "" {
		clog.Warn(ctx, "Missing password in form")
		fl := &Flash{ErrFlashLvl, "Missing form data: password"}
		f.renderForm(w, r, SetPWTmpl, SetPWTitle, fl, http.StatusBadRequest)
		return
	}

	reply, err := f.Client.ChangeUserPw(ctx,
		&auth.NewUserPassword{
			Credential:  &auth.NewUserPassword_ResetToken{ResetToken: tkn},
			NewPassword: npw,
		})
	if err == nil && reply.Success {
		f.setPWRedirect(w, r)
		return
	}

	s, ok := status.FromError(err)
	if !ok || s.Code() != codes.Unauthenticated {
		clog.Error(ctx, "ChangeUserPw gRPC call", "err", err)
		f.renderForm(w, r, SetPWTmpl, SetPWTitle,
			&Flash{ErrFlashLvl, "Internal server error"},
			http.StatusInternalServerError,
		)
	} else {
		clog.Info(ctx, "ChangeUserPw gRPC call", "err", err)
		if err := f.EP.Render(w, &ehtml.Data{Req: r, Code: http.StatusUnauthorized, Msg: "Token verification failed, please request a new one."}); err != nil {
			clog.Error(ctx, "During handling error", "err", err)
		}
	}
}

// SetPWHandler returns the handler taking care
// of password setting, using a reset token.
// GET serves the "setpw" form template.
// POST checks the JWT and sets the new password over gRPC.
func (f *Forms) SetPWHandler() http.Handler {
	return &setPWHandler{f}
}

type setPWHandler struct {
	*Forms
}

func (h *setPWHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(clog.AddArgs(r.Context(), "pkg", "authenticator.forms", "handler", "SetPW"))

	switch r.Method {
	case http.MethodGet:
		h.setPWGet(w, r)
	case http.MethodPost:
		h.setPWPost(w, r)
	default:
		w.Header().Add("Allow", AllowedMethods)
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
