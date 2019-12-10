package main

import (
	"context"
	"flag"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/moapis/authenticator/models"
	"github.com/moapis/multidb"
)

func tmplPaths(names ...string) []string {
	paths := make([]string, len(names))
	for i, n := range names {
		paths[i] = strings.Join([]string{conf.Templates, n}, "/")
	}
	return paths
}

type tmplData struct {
	Content interface{} // Data for the "content" template
}

func isInternalError(w http.ResponseWriter, err error) bool {
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error"))
		return true
	}
	return false
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles(tmplPaths("home.html", "base.html")...))
	tmpl.ExecuteTemplate(w, "base", nil)
}

type action struct {
	Name string
	URL  string
}

type listEntry struct {
	ID      int
	Name    string
	Created string
	Updated string
}

const (
	listDate = "_2 jan 06 15:04"
)

var (
	userActions = []string{
		"view",
		"reset password",
		"delete",
	}
)

func userList(ctx context.Context) ([]listEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := mdb.MultiTx(ctx, nil, conf.SQLRoutines)
	if err != nil {
		return nil, err
	}
	users, err := models.Users().All(ctx, tx)
	if err != nil {
		return nil, err
	}
	list := make([]listEntry, len(users))
	for i, u := range users {
		list[i] = listEntry{
			ID:      u.ID,
			Name:    u.Name,
			Created: u.CreatedAt.Format(listDate),
			Updated: u.CreatedAt.Format(listDate),
		}
	}
	return list, nil
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	list, err := userList(r.Context())
	if isInternalError(w, err) {
		return
	}
	tmpl := template.Must(template.ParseFiles(tmplPaths("users.html", "base.html")...))
	tmpl.ExecuteTemplate(w, "base", tmplData{Content: list})
}

var (
	conf *ServerConfig
	mdb  *multidb.MultiDB
)

func main() {
	flag.Parse()
	var err error
	if conf, err = configure(Default); err != nil {
		log.Fatal(err)
	}
	if mdb, err = conf.MultiDB.Open(); err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()

	fs := http.FileServer(http.Dir(conf.AdminLTE))
	r.PathPrefix("/dist/").Handler(fs)
	r.PathPrefix("/plugins/").Handler(fs)

	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/users", usersHandler)
	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:1234",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
