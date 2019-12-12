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
	Title       string
	BreadCrumbs []breadCrumb
	Content     interface{} // Data for the "content" template
}

func isInternalError(entry *logrus.Entry, w http.ResponseWriter, err error) bool {
	if err != nil {
		entry.WithError(err).Error("Internal server error")
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

func groupList(ctx context.Context, exec boil.ContextExecutor) ([]listEntry, error) {
	groups, err := models.Groups().All(ctx, exec)
	if err != nil {
		return nil, err
	}

	list := make([]listEntry, len(groups))
	for i, g := range groups {
		list[i] = listEntry{
			ID:      g.ID,
			Name:    g.Name,
			Created: g.CreatedAt.Format(time.RFC3339),
			Updated: g.CreatedAt.Format(time.RFC3339),
			Actions: []action{
				{"delete", fmt.Sprintf("/groups/delete/%d", g.ID), http.MethodDelete},
			},
		}
	}
	return list, nil
}

func audienceList(ctx context.Context, exec boil.ContextExecutor) ([]listEntry, error) {
	audiences, err := models.Audiences().All(ctx, exec)
	if err != nil {
		return nil, err
	}

	list := make([]listEntry, len(audiences))
	for i, a := range audiences {
		list[i] = listEntry{
			ID:      a.ID,
			Name:    a.Name,
			Created: a.CreatedAt.Format(time.RFC3339),
			Updated: a.CreatedAt.Format(time.RFC3339),
			Actions: []action{
				{"delete", fmt.Sprintf("/audiences/delete/%d", a.ID), http.MethodDelete},
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
	resource, id, err := getActionVars(w, r)
	if err != nil {
		return
	}
	entry := log.WithFields(logrus.Fields{"handler": "deleteHandler", "resource": resource, "id": id})

	tx, err := mdb.MasterTx(r.Context(), nil)
	if isInternalError(entry, w, err) {
		return
	}
	defer tx.Rollback()

	var rows int64
	switch resource {
	case "users":
		rows, err = models.Users(models.UserWhere.ID.EQ(id)).DeleteAll(r.Context(), tx)
	case "groups":
		rows, err = models.Groups(models.GroupWhere.ID.EQ(id)).DeleteAll(r.Context(), tx)
	case "audiences":
		rows, err = models.Audiences(models.AudienceWhere.ID.EQ(id)).DeleteAll(r.Context(), tx)
	default:
		entry.Warn("Unknown resource")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Unknown resource"))
		return
	}
	entry = entry.WithField("rows", rows)
	if isInternalError(entry, w, err) {
		return
	}
	if rows == 0 {
		log.Warn("Not found")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(fmt.Sprintf("%s %d not found", strings.TrimSuffix(resource, "s"), id)))
		return
	}
	if isInternalError(entry, w, tx.Commit()) {
		return
	}
	entry.Info("Deleted")
	w.Write([]byte(fmt.Sprintf("%s %d successfully deleted", strings.TrimSuffix(resource, "s"), id)))
}

type breadCrumb struct {
	Name string
	URL  string
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	resource := mux.Vars(r)["resource"]
	entry := log.WithFields(logrus.Fields{"handler": "listHandler", "resource": resource})

	tx, err := mdb.MultiTx(r.Context(), &sql.TxOptions{ReadOnly: true}, conf.SQLRoutines)
	if isInternalError(entry, w, err) {
		return
	}
	defer tx.Rollback()

	var list []listEntry
	switch resource {
	case "users":
		list, err = userList(r.Context(), tx)
	case "groups":
		list, err = groupList(r.Context(), tx)
	case "audiences":
		list, err = audienceList(r.Context(), tx)
	default:
		entry.Warn("Unknown resource")
		http.NotFound(w, r)
		return
	}
	if isInternalError(entry, w, err) {
		return
	}
	entry = entry.WithField("list", list)

	tmpl, err := template.ParseFiles(tmplPaths("list.html", "base.html")...)
	if isInternalError(entry, w, err) {
		return
	}

	tmpl.ExecuteTemplate(w, "base", tmplData{
		Title: fmt.Sprintf("%s List", strings.Title(strings.TrimSuffix(resource, "s"))),
		BreadCrumbs: []breadCrumb{
			{"Home", "/"},
			{resource, ""},
		},
		Content: list,
	})
	entry.Debug("Served")
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
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/{resource}/", listHandler)

	r.Path("/{resource}/delete/{id}").Methods("DELETE").HandlerFunc(deleteHandler)

	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:1234",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
