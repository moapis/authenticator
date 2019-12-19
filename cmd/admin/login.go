package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	pb "github.com/moapis/authenticator/pb"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func loginParseForm(w http.ResponseWriter, r *http.Request) (string, error) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("%d Bad request: Form data", http.StatusBadRequest)))
		return "", err
	}
	redirect := r.Form.Get("redirect")
	if redirect == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("%d Bad request: missing redirect", http.StatusBadRequest)))
		return "", errors.New("Empty redirect")
	}
	return redirect, nil
}

const (
	loginTitle = "Please Login"
)

type loginRedirect struct {
	Redirect string
}

func loginTemplate(entry *logrus.Entry, w http.ResponseWriter, redirect, errMsg string, status ...int) {
	tmpl, err := template.ParseFiles(tmplPaths("login.html", "base.html")...)
	if isInternalError(entry, w, err) {
		return
	}
	if status != nil {
		w.WriteHeader(status[0])
	}
	if err = tmpl.ExecuteTemplate(w, "base",
		tmplData{
			Title:   loginTitle,
			Error:   errMsg,
			Content: loginRedirect{redirect},
		},
	); err != nil {
		entry.WithError(err).Error("ExecuteTemplate")
	}
	entry.Debug("Served")
}

func loginFormHandler(w http.ResponseWriter, r *http.Request) {
	entry := r.Context().Value(logEntry).(*logrus.Entry).WithFields(logrus.Fields{"handler": "loginFormHandler"})
	redirect, err := loginParseForm(w, r)
	if err != nil {
		entry.WithError(err).Warn("Bad request")
		return
	}
	entry = entry.WithField("redirect", redirect)
	loginTemplate(entry, w, redirect, "")
}

func loginPostHandler(w http.ResponseWriter, r *http.Request) {
	entry := r.Context().Value(logEntry).(*logrus.Entry).WithFields(logrus.Fields{"handler": "loginPostHandler"})
	redirect, err := loginParseForm(w, r)
	if err != nil {
		entry.WithError(err).Warn("Bad request")
		return
	}
	entry = entry.WithField("redirect", redirect)

	email, password := r.PostForm.Get("email"), r.PostForm.Get("password")
	if email == "" || password == "" {
		log.Warn("Missing email or password")
		loginTemplate(entry, w, redirect, "Missing email or password", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	auth, err := authClient.AuthenticatePwUser(ctx, &pb.UserPassword{
		User:     &pb.UserPassword_Email{Email: email},
		Password: password,
	})
	if err != nil {
		entry = entry.WithError(err)
		s, ok := status.FromError(err)
		if !ok || s.Code() != codes.Unauthenticated {
			entry.Error("gRPC call")
			loginTemplate(entry, w, redirect, "Internal server error", http.StatusInternalServerError)
		} else {
			entry.Warn("gRPC call")
			loginTemplate(entry, w, redirect, "Wrong email or password", http.StatusUnauthorized)
		}
		return
	}
	http.Redirect(w, r, strings.Join([]string{redirect, "?jwt=", auth.GetJwt()}, ""), http.StatusSeeOther)
	entry.Debug("Redirect done")
}

func passwordFormHandler(w http.ResponseWriter, r *http.Request) {
	entry := r.Context().Value(logEntry).(*logrus.Entry).WithFields(logrus.Fields{"handler": "passwordFormHandler"})

	jwt := r.URL.Query().Get("token")
	if jwt == "" {
		entry.Warn("Token not in URL")
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}
	claims, err := verificator.Token(r.Context(), jwt)
	if err != nil {
		entry.WithError(err).Warn("Invalid token")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	entry.WithField("claims", claims).Debug("Token verified")

	tmpl, err := template.ParseFiles(tmplPaths("password.html", "base.html")...)
	if isInternalError(entry, w, err) {
		return
	}
	if err = tmpl.ExecuteTemplate(w, "base",
		tmplData{
			Title:   "Set new password",
			Content: claims,
		},
	); err != nil {
		entry.WithError(err).Error("ExecuteTemplate")
	}
	entry.Debug("Served")
}

func passwordPostHandler(w http.ResponseWriter, r *http.Request) {
	entry := r.Context().Value(logEntry).(*logrus.Entry).WithFields(logrus.Fields{"handler": "passwordPostHandler"})

	if err := r.ParseForm(); err != nil {
		entry.WithError(err).Warn("Bad request")
		http.Error(w, "Invalid post data", http.StatusBadRequest)
	}
	jwt, password := r.FormValue("token"), r.FormValue("password")
	if jwt == "" || password == "" {
		entry.WithFields(logrus.Fields{"token": jwt, "password": password}).Warn("Missing data")
		http.Error(w, "Missing some data", http.StatusBadRequest)
	}

	reply, err := authClient.ChangeUserPw(r.Context(),
		&pb.NewUserPassword{
			NewPassword: password,
			Credential:  &pb.NewUserPassword_ResetToken{ResetToken: jwt},
		},
	)
	if err != nil {
		entry = entry.WithError(err)
		s, ok := status.FromError(err)
		if !ok || s.Code() != codes.Unauthenticated {
			entry.Error("gRPC call")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		} else {
			entry.Warn("gRPC call")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
		}
		return
	}
	entry.WithField("success", reply.GetSuccess()).Info("Password reset")
	if _, err := w.Write([]byte("Password set successfully!\r\nYou can now close this window.")); err != nil {
		entry.WithError(err).Error("Writing response")
	}
	entry.Debug("Served")
}
