package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"text/template"
	"time"

	pb "github.com/moapis/authenticator/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type templateData struct {
	Redirect string
	Error    string
}

type loginHandler struct {
	client pb.AuthenticatorClient
	tmpl   *template.Template
}

func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/login" {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("%d Bad request: Form data", http.StatusBadRequest)))
		return
	}

	redirect := r.Form.Get("redirect")
	if redirect == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("%d Bad request: missing redirect", http.StatusBadRequest)))
		return
	}
	if r.Method != http.MethodPost {
		h.tmpl.Execute(w, templateData{Redirect: redirect})
		return
	}
	h.postRequest(w, r, redirect)
}

func (h *loginHandler) postRequest(w http.ResponseWriter, r *http.Request, redirect string) {
	email, password := r.PostForm.Get("email"), r.PostForm.Get("password")
	if email == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		h.tmpl.Execute(w, templateData{redirect, "Missing email or password"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	auth, err := h.client.AuthenticatePwUser(ctx, &pb.UserPassword{
		User:     &pb.UserPassword_Email{Email: email},
		Password: password,
	})
	if err != nil {
		log.Println(err.Error())
		s, ok := status.FromError(err)
		if !ok || s.Code() != codes.Unauthenticated {
			w.WriteHeader(http.StatusInternalServerError)
			h.tmpl.Execute(w, templateData{redirect, "Internal server error"})
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			h.tmpl.Execute(w, templateData{redirect, "Wrong email or password"})
		}
		return
	}
	http.Redirect(w, r, strings.Join([]string{redirect, "?jwt=", auth.GetJwt()}, ""), http.StatusSeeOther)
}

var (
	authServer   = flag.String("authServer", "127.0.0.1:8765", "Host and port for the authenticator server")
	listenAddr   = flag.String("listen", "127.0.0.1:8080", "List address and port")
	templateFile = flag.String("template", "templates/login.html", "HTML template file")
)

func main() {
	flag.Parse()

	cc, err := grpc.Dial(*authServer, grpc.WithBlock(), grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	defer cc.Close()

	client := pb.NewAuthenticatorClient(cc)

	log.Println("HTTP server starting")
	http.ListenAndServe(*listenAddr, &loginHandler{
		client,
		template.Must(template.ParseFiles(*templateFile)),
	})
}
