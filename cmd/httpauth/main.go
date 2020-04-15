// Copyright (c) 2020, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	"github.com/inconshreveable/log15/ext"
	auth "github.com/moapis/authenticator"
	"github.com/moapis/authenticator/forms"
	"github.com/moapis/ehtml"
	clog "github.com/usrpro/clog15"
)

func (c *ServerConfig) listen(sc chan os.Signal, h http.Handler) error {
	s := &http.Server{
		Addr:         addrString(c.Address, c.Port),
		Handler:      h,
		ReadTimeout:  c.Timeout,
		WriteTimeout: c.Timeout,
	}

	log15.Debug("Starting server", "conf", c, "serv", s)

	signal.Notify(sc, os.Interrupt)

	ec := make(chan error, 1)
	go func(ec chan<- error) {
		if c.TLS == nil {
			ec <- s.ListenAndServe()
		} else {
			ec <- s.ListenAndServeTLS(c.TLS.CertFile, c.TLS.KeyFile)
		}
	}(ec)

	for {
		select {
		case err := <-ec:
			signal.Stop(sc)
			return fmt.Errorf("Server shutdown: %w", err)
		case sig := <-sc:
			log15.Info("Received signal", "sig", sig)

			ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
			defer cancel()

			if err := s.Shutdown(ctx); err != nil {
				return fmt.Errorf("Server shutdown: %w", err)
			}
		}
	}
}

func fatalRun(err error) int {
	log15.Crit("Terminating main; run():", "err", err)
	return 1
}

type reqIDKey struct{}

var reqID reqIDKey

func (c *ServerConfig) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), c.Timeout)
		defer cancel()

		start := time.Now()
		id := ext.RandId(5)

		ctx = clog.NewLogger(ctx, "id", id, "uri", r.URL.Path)
		r = r.WithContext(context.WithValue(ctx, reqID, id))

		next.ServeHTTP(w, r)

		clog.Info(ctx, r.Method, "t", time.Now().Sub(start))
	})
}

var configFiles = flag.String("config", "", "Comma separated list of JSON config files")

func run(dc *ServerConfig) int {
	conf, err := configure(dc, strings.Split(*configFiles, ",")...)
	if err != nil {
		return fatalRun(err)
	}

	tmpl, err := template.ParseGlob(conf.TemplateGlob)
	if err != nil {
		return fatalRun(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cc, err := conf.AuthServer.dial(ctx)
	if err != nil {
		return fatalRun(err)
	}
	defer cc.Close()

	f := &forms.Forms{
		Tmpl:   tmpl,
		EP:     ehtml.Pages{Tmpl: tmpl},
		Data:   conf.Data,
		Client: auth.NewAuthenticatorClient(cc),
		Paths: &forms.Paths{
			ServerAddress: conf.ServerAddress,
		},
	}

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static", http.FileServer(http.Dir(conf.Static))))
	mux.Handle(forms.DefaultSetPWPath, f.SetPWHandler())
	mux.Handle(forms.DefaultResetPWPath, f.ResetPWHandler())
	mux.Handle(forms.DefaultLoginPath, f.LoginHander())

	if err = conf.listen(make(chan os.Signal, 1), conf.middleware(mux)); !errors.Is(err, http.ErrServerClosed) {
		return fatalRun(err)
	}

	log15.Info(err.Error())
	return 0
}

func main() {
	flag.Parse()
	os.Exit(run(&Default))
}
