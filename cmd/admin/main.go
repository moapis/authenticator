package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/moapis/authenticator/models"
	"github.com/moapis/multidb"
	"github.com/volatiletech/sqlboiler/boil"
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
	Actions []action
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

func userList(ctx context.Context, exec boil.ContextExecutor) ([]listEntry, error) {
	users, err := models.Users().All(ctx, exec)
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
			Actions: make([]action, len(userActions)),
		}
		for n, name := range userActions {
			list[i].Actions[n] = action{
				Name: name,
				URL:  url.PathEscape(fmt.Sprintf("/users/%s/%d", name, u.ID)),
			}
		}
	}
	return list, nil
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	tx, err := mdb.MultiTx(ctx, &sql.TxOptions{ReadOnly: true}, conf.SQLRoutines)
	if isInternalError(w, err) {
		return
	}
	defer tx.Rollback()

	var list []listEntry
	switch strings.Trim(r.URL.Path, "/") {
	case "users":
		list, err = userList(ctx, tx)
	default:
		http.NotFound(w, r)
		return
	}
	if isInternalError(w, err) {
		return
	}
	tmpl := template.Must(template.ParseFiles(tmplPaths("list.html", "base.html")...))
	tmpl.ExecuteTemplate(w, "base", tmplData{Content: list})
}

var (
	conf      *ServerConfig
	mdb       *multidb.MultiDB
	listPaths = []string{"/users"}
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

	for _, p := range listPaths {
		r.HandleFunc(p, listHandler)
	}
	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:1234",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
