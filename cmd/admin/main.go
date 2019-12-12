package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/moapis/authenticator/models"
	"github.com/moapis/multidb"
	"github.com/sirupsen/logrus"
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
	Name   string
	URL    string
	Method string
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
			Created: u.CreatedAt.Format(time.RFC3339),
			Updated: u.CreatedAt.Format(time.RFC3339),
			Actions: []action{
				{"reset password", fmt.Sprintf("/users/reset/%d", u.ID), http.MethodPut},
				{"delete", fmt.Sprintf("/users/delete/%d", u.ID), http.MethodDelete},
			},
		}
	}
	return list, nil
}

const (
	errIntConv = "Parse %s of value %s: %w"
)

func getActionVars(w http.ResponseWriter, r *http.Request) (string, int, error) {
	v := mux.Vars(r)
	id, err := strconv.Atoi(v["id"])
	if err != nil {
		err := fmt.Errorf(errIntConv, "ID", v["id"], err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return "", 0, err
	}
	return v["resource"], id, nil
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	tx, err := mdb.MasterTx(r.Context(), nil)
	if isInternalError(w, err) {
		return
	}
	defer tx.Rollback()

	resource, id, err := getActionVars(w, r)
	if err != nil {
		return
	}
	log := log.WithFields(logrus.Fields{"resource": resource, "id": id})

	var affected int64
	switch resource {
	case "users":
		affected, err = models.Users(models.UserWhere.ID.EQ(id)).DeleteAll(r.Context(), tx)
	default:
		log.Warn("Unknown resource")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Unknown resource"))
		return
	}
	if isInternalError(w, err) {
		return
	}

	if affected == 0 {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(fmt.Sprintf("%s %d not found", strings.TrimSuffix(resource, "s"), id)))
		return
	}
	w.Write([]byte(fmt.Sprintf("%s %d successfully deleted", strings.TrimSuffix(resource, "s"), id)))
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	tx, err := mdb.MultiTx(r.Context(), &sql.TxOptions{ReadOnly: true}, conf.SQLRoutines)
	if isInternalError(w, err) {
		return
	}
	defer tx.Rollback()

	var list []listEntry
	switch mux.Vars(r)["resource"] {
	case "users":
		list, err = userList(r.Context(), tx)
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
	conf  *ServerConfig
	mdb   *multidb.MultiDB
	paths = []string{"/users"}
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
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/{resource}", listHandler)

	r.Path("/{resource}/delete/{id}").Methods("DELETE").HandlerFunc(deleteHandler)

	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:1234",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
