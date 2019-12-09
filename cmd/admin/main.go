package main

import (
	"flag"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

var (
	adminlteDir  = flag.String("adminlte", "./AdminLTE", "directory with AdminLTE assets")
	authServer   = flag.String("authServer", "127.0.0.1:8765", "Host and port for the authenticator server")
	templateFile = flag.String("template", "templates/base.html", "HTML template file")
)

func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles(*templateFile))
	tmpl.Execute(w, nil)
}

func main() {
	flag.Parse()

	r := mux.NewRouter()

	fs := http.FileServer(http.Dir(*adminlteDir))
	r.PathPrefix("/dist/").Handler(fs)
	r.PathPrefix("/plugins/").Handler(fs)

	r.HandleFunc("/", homeHandler)
	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:1234",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
