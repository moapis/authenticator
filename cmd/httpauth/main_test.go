// Copyright (c) 2020, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/inconshreveable/log15"
	clog "github.com/usrpro/clog15"
)

func TestServerConfig_listen(t *testing.T) {
	type fields struct {
		Address string
		Port    uint16
		Timeout time.Duration
		TLS     *TLSConfig
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			"Listen error",
			fields{
				Port: 80,
			},
			true,
		},
		{
			"TLS error",
			fields{
				Address: "127.0.0.1",
				Port:    7777,
				TLS: &TLSConfig{
					"foo",
					"bar",
				},
			},
			true,
		},
		{
			"Success listen & shutdown",
			fields{
				Address: "127.0.0.1",
				Port:    7777,
				Timeout: time.Minute,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ServerConfig{
				Address: tt.fields.Address,
				Port:    tt.fields.Port,
				Timeout: tt.fields.Timeout,
				TLS:     tt.fields.TLS,
			}

			sc := make(chan os.Signal, 2)

			go func() {
				<-time.After(10 * time.Millisecond)
				sc <- os.Interrupt
			}()

			err := c.listen(sc, nil)
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("ServerConfig.listen() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_fatalRun(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{
			"Error",
			errors.New("testing"),
			1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fatalRun(tt.err); got != tt.want {
				t.Errorf("fatalRun() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_run(t *testing.T) {
	eConf := Default
	eConf.Port = 80

	tmplEConf := Default
	tmplEConf.TemplateGlob = "foo"

	tests := []struct {
		name  string
		files string
		d     *ServerConfig
		want  int
	}{
		{
			"Succesfull start and shutdown",
			"",
			&Default,
			0,
		},
		{
			"Config error",
			"foo",
			&Default,
			1,
		},
		{
			"Template error",
			"",
			&tmplEConf,
			1,
		},
		{
			"Listen error",
			"",
			&eConf,
			1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configFiles = &tt.files

			if tt.want == 0 {
				go func() {
					p, _ := os.FindProcess(os.Getpid())
					<-time.After(100 * time.Millisecond)
					p.Signal(os.Interrupt)
				}()
			}

			if got := run(tt.d); got != tt.want {
				t.Errorf("run() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServerConfig_middleware(t *testing.T) {
	c := ServerConfig{Timeout: 5 * time.Second}
	n := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if _, ok := ctx.Deadline(); !ok {
			t.Error("Context Deadline not set")
		}

		if _, ok := ctx.Value(reqID).(string); !ok {
			t.Error("RequestID not set in context")
		}

		if _, ok := ctx.Value(clog.CtxLogger).(log15.Logger); !ok {
			t.Error("Logger not set in context")
		}
	})

	h := c.middleware(n)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://example.com/login", nil)

	h.ServeHTTP(w, r)
}
