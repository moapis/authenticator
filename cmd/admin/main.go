package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	auth "github.com/moapis/authenticator"
	"github.com/moapis/authenticator/middleware"
	"github.com/moapis/authenticator/models"
	"github.com/moapis/authenticator/verify"
	"github.com/moapis/multidb"
	"github.com/sirupsen/logrus"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"github.com/volatiletech/sqlboiler/v4/queries"
	"github.com/volatiletech/sqlboiler/v4/queries/qm"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	AuthPrefix  string
	BreadCrumbs []breadCrumb
	Panel       bool
	Error       string
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

type action struct {
	Name   string
	URL    string
	Method string
}

type listContents struct {
	Resource string
	List     []listEntry
}

type listEntry struct {
	ID      int
	Name    string
	Created string
	Updated string
	Actions []action
}

const (
	listDate      = "_2 jan 06 15:04"
	indexRedirect = "/users/"
)

func userActions(id int) []action {
	return []action{
		{"reset password", fmt.Sprintf("/users/reset/%d", id), http.MethodPut},
		{"delete", fmt.Sprintf("/users/delete/%d", id), http.MethodDelete},
	}
}

func userList(ctx context.Context, exec boil.ContextExecutor) (*listContents, error) {
	users, err := models.Users(qm.OrderBy(models.UserColumns.ID)).All(ctx, exec)
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
			Actions: userActions(u.ID),
		}
	}
	return &listContents{"users", list}, nil
}

func groupList(ctx context.Context, exec boil.ContextExecutor) (*listContents, error) {
	groups, err := models.Groups(qm.OrderBy(models.GroupColumns.ID)).All(ctx, exec)
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
	return &listContents{"groups", list}, nil
}

func audienceList(ctx context.Context, exec boil.ContextExecutor) (*listContents, error) {
	audiences, err := models.Audiences(qm.OrderBy(models.AudienceColumns.ID)).All(ctx, exec)
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
	return &listContents{"audiences", list}, nil
}

const (
	errIntConv      = "Parse %s of value %s: %w"
	errMissingField = "Missing %s field data in form"
)

func aToiMap(entry *logrus.Entry, vars map[string]string) map[string]int {
	intMap := make(map[string]int)
	for k, v := range vars {
		i, err := strconv.Atoi(v)
		if err != nil {
			entry.WithError(fmt.Errorf(errIntConv, "ID", v, err)).Debug("Skipped")
			continue
		}
		intMap[k] = i
	}
	return intMap
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	entry := r.Context().Value(logEntry).(*logrus.Entry).WithFields(logrus.Fields{"handler": "deleteHandler", "vars": vars})
	id := aToiMap(entry, vars)["id"]

	tx, err := mdb.MasterTx(r.Context(), nil)
	if isInternalError(entry, w, err) {
		return
	}
	defer tx.Rollback()

	var rows int64
	switch vars["resource"] {
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
		w.Write([]byte(fmt.Sprintf("%s %d not found", strings.TrimSuffix(vars["resource"], "s"), id)))
		return
	}
	if isInternalError(entry, w, tx.Commit()) {
		return
	}
	entry.Info("Deleted")
	w.Write([]byte(fmt.Sprintf("%s %d successfully deleted", strings.TrimSuffix(vars["resource"], "s"), id)))
}

type breadCrumb struct {
	Name string
	URL  string
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	entry := r.Context().Value(logEntry).(*logrus.Entry).WithFields(logrus.Fields{"handler": "listHandler", "vars": vars})

	tx, err := mdb.MultiTx(r.Context(), nil, conf.SQLRoutines)
	if isInternalError(entry, w, err) {
		return
	}
	defer tx.Rollback()

	var content *listContents
	switch vars["resource"] {
	case "users":
		content, err = userList(r.Context(), tx)
	case "groups":
		content, err = groupList(r.Context(), tx)
	case "audiences":
		content, err = audienceList(r.Context(), tx)
	default:
		entry.Warn("Unknown resource")
		http.NotFound(w, r)
		return
	}
	if isInternalError(entry, w, err) {
		return
	}
	entry = entry.WithField("list", content)

	tmpl, err := template.ParseFiles(tmplPaths("list.html", "panel.html", "base.html")...)
	if isInternalError(entry, w, err) {
		return
	}

	tmpl.ExecuteTemplate(w, "base", tmplData{
		Title: fmt.Sprintf("%s List", strings.Title(strings.TrimSuffix(vars["resource"], "s"))),
		Panel: true,
		BreadCrumbs: []breadCrumb{
			{"Home", "/"},
			{vars["resource"], ""},
		},
		Content: content,
	})
	entry.Debug("Served")
}

type userView struct {
	*models.User
	Actions []action
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	entry := r.Context().Value(logEntry).(*logrus.Entry).WithFields(logrus.Fields{"handler": "userHandler", "vars": vars})
	id := aToiMap(entry, vars)["id"]

	tx, err := mdb.MultiTx(r.Context(), nil, conf.SQLRoutines)
	if isInternalError(entry, w, err) {
		return
	}
	defer tx.Rollback()

	um, err := models.Users(
		models.UserWhere.ID.EQ(id),
		qm.Load(models.UserRels.Password),
		qm.Load(models.UserRels.Groups),
		qm.Load(models.UserRels.Audiences),
	).One(r.Context(), tx)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	} else if isInternalError(entry, w, err) {
		return
	}
	entry = entry.WithFields(logrus.Fields{"user": um, "groups": um.R.Groups, "audiences": um.R.Audiences})

	tmpl, err := template.ParseFiles(tmplPaths("user.html", "panel.html", "base.html")...)
	if isInternalError(entry, w, err) {
		return
	}

	if err = tmpl.ExecuteTemplate(w, "base", tmplData{
		Title: fmt.Sprintf("User %d", id),
		Panel: true,
		BreadCrumbs: []breadCrumb{
			{"Home", "/"},
			{"Users", "../"},
			{strconv.Itoa(id), ""},
		},
		Content: userView{um, userActions(id)},
	}); err != nil {
		entry.WithError(err).Error("ExecuteTemplate")
	}
	entry.Debug("Served")
}

func removeUserRelationHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	entry := r.Context().Value(logEntry).(*logrus.Entry).WithFields(logrus.Fields{"handler": "removeUserRelationHandler", "vars": vars})
	iv := aToiMap(entry, vars)

	tx, err := mdb.MasterTx(r.Context(), nil)
	if isInternalError(entry, w, err) {
		return
	}
	defer tx.Rollback()

	um := &models.User{ID: iv["id"]}
	switch vars["relation"] {
	case "groups":
		err = um.RemoveGroups(r.Context(), tx, &models.Group{ID: iv["rid"]})
	case "audiences":
		err = um.RemoveAudiences(r.Context(), tx, &models.Audience{ID: iv["rid"]})
	}
	if isInternalError(entry, w, err) {
		return
	}
	if err = tx.Commit(); isInternalError(entry, w, err) {
		return
	}
	entry.Info("Removed user relation")
	if _, err = w.Write([]byte(
		fmt.Sprintf(
			"%s %d successfully removed from user %d",
			strings.TrimSuffix(vars["relation"], "s"),
			iv["rid"], iv["id"],
		),
	)); err != nil {
		entry.WithError(err).Error("Writing response")
	}
	entry.Debug("Served")
}

func newEntityFormHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	entry := r.Context().Value(logEntry).(*logrus.Entry).WithFields(logrus.Fields{"handler": "newEntityFormHandler", "vars": vars})

	var (
		tmpl *template.Template
		err  error
	)
	switch vars["resource"] {
	case "groups", "audiences":
		tmpl, err = template.ParseFiles(tmplPaths("new_relation.html", "panel.html", "base.html")...)
	case "users":
		tmpl, err = template.ParseFiles(tmplPaths("new_user.html", "panel.html", "base.html")...)
	default:
		http.NotFound(w, r)
		log.Info("Resource not found")
		return
	}
	if isInternalError(entry, w, err) {
		return
	}
	plural := strings.Title(vars["resource"])
	single := strings.TrimSuffix(plural, "s")
	if err = tmpl.ExecuteTemplate(w, "base", tmplData{
		Title: fmt.Sprintf("New %s", single),
		Panel: true,
		BreadCrumbs: []breadCrumb{
			{"Home", "/"},
			{plural, fmt.Sprintf("/%s/", vars["resource"])},
			{"New", ""},
		},
		Content: struct{ Name string }{single},
	}); err != nil {
		entry.WithError(err).Error("ExecuteTemplate")
	}
	entry.Debug("Served")
}

func parseForm(w http.ResponseWriter, r *http.Request, fields []string) (map[string]string, error) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("%d Bad request: Form data", http.StatusBadRequest)))
		return nil, err
	}
	formData := make(map[string]string)
	for _, f := range fields {
		data := strings.TrimSpace(r.PostForm.Get(f))
		if data == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("%d Bad request: Missing %s", http.StatusBadRequest, f)))
			return nil, fmt.Errorf(errMissingField, f)
		}
		formData[f] = data
	}
	return formData, nil
}

func newRelation(w http.ResponseWriter, r *http.Request, entry *logrus.Entry, relation string) {
	data, err := parseForm(w, r, []string{"name", "description"})
	if err != nil {
		entry.WithError(err).Warn("parseForm")
		return
	}
	entry = entry.WithField("data", data)

	tx, err := mdb.MasterTx(r.Context(), nil)
	if isInternalError(entry, w, err) {
		return
	}
	defer tx.Rollback()

	var id int
	switch relation {
	case "groups":
		group := models.Group{Name: data["name"], Description: data["description"]}
		err = group.Insert(r.Context(), tx, boil.Infer())
		entry = entry.WithField("group", group)
		id = group.ID
	case "audiences":
		audience := models.Audience{Name: data["name"], Description: data["description"]}
		err = audience.Insert(r.Context(), tx, boil.Infer())
		entry = entry.WithField("audience", audience)
		id = audience.ID
	}
	if isInternalError(entry, w, err) {
		return
	}
	if err := tx.Commit(); isInternalError(entry, w, err) {
		return
	}
	entry.Info("New relation")
	http.Redirect(w, r, fmt.Sprintf("/%s/%d/", relation, id), http.StatusSeeOther)
}

func newGroupPostHandler(w http.ResponseWriter, r *http.Request) {
	entry := r.Context().Value(logEntry).(*logrus.Entry).WithFields(logrus.Fields{"handler": "newGroupPostHandler"})
	newRelation(w, r, entry, "groups")
}

func newAudiencePostHandler(w http.ResponseWriter, r *http.Request) {
	entry := r.Context().Value(logEntry).(*logrus.Entry).WithFields(logrus.Fields{"handler": "newAudiencePostHandler"})
	newRelation(w, r, entry, "audiences")
}

func newUserPostHandler(w http.ResponseWriter, r *http.Request) {
	entry := r.Context().Value(logEntry).(*logrus.Entry).WithFields(logrus.Fields{"handler": "newUserPostHandler"})
	data, err := parseForm(w, r, []string{"email", "name"})
	if err != nil {
		entry.WithError(err).Warn("parseForm")
		return
	}
	entry = entry.WithField("data", data)

	reply, err := authClient.RegisterPwUser(r.Context(), &auth.RegistrationData{
		Email: data["email"],
		Name:  data["name"],
		Url: &auth.CallBackUrl{
			BaseUrl:  fmt.Sprintf("%s/password", conf.ServerAddress),
			TokenKey: "token",
		},
	})
	switch status.Code(err) {
	case codes.OK:
		break
	case codes.InvalidArgument:
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("%d Bad request: Invalid arguments in gRPC call", http.StatusBadRequest)))
		entry.WithError(err).Error("authClient.RegisterPwUser")
		return
	default:
		isInternalError(entry, w, err)
		return
	}
	entry = entry.WithField("reply", *reply)

	entry.Info("New user")
	http.Redirect(w, r, fmt.Sprintf("/%s/%d/", "users", reply.UserId), http.StatusSeeOther)
}

const (
	availableGroupsQuery = `
	select * 
	from auth.groups
	where id not in (
		select group_id
		from auth.user_groups
		where user_id = $1
	);`
	availableAudiencesQuery = `
	select * 
	from auth.audiences
	where id not in (
		select audience_id
		from auth.user_audiences
		where user_id = $1
	);`
)

func listAvailableRelationsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	entry := r.Context().Value(logEntry).(*logrus.Entry).WithFields(logrus.Fields{"handler": "listAvailableRelationsHandler", "vars": vars})
	iv := aToiMap(entry, vars)

	tx, err := mdb.MultiTx(r.Context(), nil, conf.SQLRoutines)
	if isInternalError(entry, w, err) {
		return
	}
	defer tx.Rollback()

	var content interface{}

	switch vars["relation"] {
	case "groups":
		var groups models.GroupSlice
		err = queries.Raw(availableGroupsQuery, iv["id"]).Bind(r.Context(), tx, &groups)
		content = groups
	case "audiences":
		var audiences models.AudienceSlice
		err = queries.Raw(availableAudiencesQuery, iv["id"]).Bind(r.Context(), tx, &audiences)
		content = audiences
	}

	if isInternalError(entry, w, err) {
		return
	}
	entry = entry.WithField("content", content)

	tmpl, err := template.ParseFiles(tmplPaths("available_relations.html", "panel.html", "base.html")...)
	if isInternalError(entry, w, err) {
		return
	}

	plural := strings.Title(vars["relation"])
	if err = tmpl.ExecuteTemplate(w, "base", tmplData{
		Title: fmt.Sprintf("Available %s for User %d", plural, iv["id"]),
		Panel: true,
		BreadCrumbs: []breadCrumb{
			{"Home", "/"},
			{"Users", "../../"},
			{strconv.Itoa(iv["id"]), "../"},
			{fmt.Sprintf("Available %s", plural), ""},
		},
		Content: content,
	}); err != nil {
		entry.WithError(err).Error("ExecuteTemplate")
	}
	entry.Debug("Served")
}

func setUserRelationHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	entry := r.Context().Value(logEntry).(*logrus.Entry).WithFields(logrus.Fields{"handler": "setUserRelation", "vars": vars})
	iv := aToiMap(entry, vars)

	tx, err := mdb.MasterTx(r.Context(), nil)
	if isInternalError(entry, w, err) {
		return
	}
	defer tx.Rollback()

	um := &models.User{ID: iv["id"]}
	switch vars["relation"] {
	case "groups":
		err = um.AddGroups(r.Context(), tx, false, &models.Group{ID: iv["rid"]})
	case "audiences":
		err = um.AddAudiences(r.Context(), tx, false, &models.Audience{ID: iv["rid"]})
	}
	if isInternalError(entry, w, err) {
		return
	}
	if err = tx.Commit(); isInternalError(entry, w, err) {
		return
	}
	entry.Info("Set user relation")
	if _, err = w.Write([]byte(
		fmt.Sprintf(
			"%s %d successfully set to user %d",
			strings.TrimSuffix(vars["relation"], "s"),
			iv["rid"], iv["id"],
		),
	)); err != nil {
		entry.WithError(err).Error("Writing response")
	}
	entry.Debug("Served")
}

type logEntryType string

var logEntry = logEntryType("entry")

func contextMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		entry := log.WithFields(logrus.Fields{"url": r.RequestURI, "reqID": rand.Int63()})
		entry.Info("Request start")
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, logEntry, entry)))

		entry.WithField("duration", time.Now().Sub(start)).Info("Request finished")
	})
}

func catchMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				log.WithFields(logrus.Fields{"value": v, "url": r.RequestURI}).Error("Recovered from panic")
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

var (
	conf        *ServerConfig
	mdb         *multidb.MultiDB
	authClient  auth.AuthenticatorClient
	verificator *verify.Verificator
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

	entry := log.WithField("address", conf.AuthServer.String())
	entry.Info("Start gRPC Dail")

	var cc *grpc.ClientConn
	for cc == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if cc, err = grpc.DialContext(ctx, conf.AuthServer.String(), grpc.WithBlock(), grpc.WithInsecure()); err != nil {
			entry.WithError(err).Error("gRPC Dail")
		}
		cancel()
	}
	defer cc.Close()

	authClient = auth.NewAuthenticatorClient(cc)
	verificator = &verify.Verificator{
		Client:    authClient,
		Audiences: conf.Audiences,
	}
	entry.Info("gRPC Dail done")

	mwc := &middleware.Client{
		Verificator:   verificator,
		LoginURL:      conf.LoginURL,
		ServerAddress: conf.ServerAddress,
		RefreshWithin: 12 * time.Hour,
	}

	r := mux.NewRouter()
	r.Use(catchMW)
	r.Use(contextMW)
	r.Use(mwc.Middleware)
	r.Handle("/", http.RedirectHandler(indexRedirect, http.StatusMovedPermanently))

	fs := http.FileServer(http.Dir(conf.AdminLTE))
	r.PathPrefix("/dist/").Handler(fs)
	r.PathPrefix("/plugins/").Handler(fs)
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	r.HandleFunc("/{resource}/", listHandler)

	r.HandleFunc("/users/{id}/", userHandler)
	r.Path("/users/{id}/{relation}/").Methods(http.MethodGet).HandlerFunc(listAvailableRelationsHandler)
	r.Path("/users/{id}/{relation}/{rid}").Methods(http.MethodPut).HandlerFunc(setUserRelationHandler)
	r.Path("/users/{id}/remove/{relation}/{rid}").Methods(http.MethodPut).HandlerFunc(removeUserRelationHandler)

	r.Path("/{resource}/delete/{id}").Methods(http.MethodDelete).HandlerFunc(deleteHandler)

	r.Path("/new/{resource}").Methods(http.MethodGet).HandlerFunc(newEntityFormHandler)
	r.Path("/new/audiences").Methods(http.MethodPost).HandlerFunc(newAudiencePostHandler)
	r.Path("/new/groups").Methods(http.MethodPost).HandlerFunc(newGroupPostHandler)
	r.Path("/new/users").Methods(http.MethodPost).HandlerFunc(newUserPostHandler)

	srv := &http.Server{
		Handler:      r,
		Addr:         fmt.Sprintf("%s:%d", conf.Address, conf.Port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
