// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/moapis/multidb"
	pg "github.com/moapis/multidb/drivers/postgresql"
	"github.com/sirupsen/logrus"
	"github.com/volatiletech/sqlboiler/v4/boil"
)

var (
	log *logrus.Logger
)

func init() {
	log = logrus.New()
	log.SetLevel(logrus.InfoLevel)
}

// LogLevel used for logrus
type LogLevel string

const (
	// PanicLevel sets logrus level to panic
	PanicLevel LogLevel = "panic"
	// FatalLevel sets logrus level to fatal
	FatalLevel LogLevel = "fatal"
	// ErrorLevel sets logrus level to error
	ErrorLevel LogLevel = "error"
	// WarnLevel sets logrus level to warn
	WarnLevel LogLevel = "warn"
	// InfoLevel sets logrus level to info
	InfoLevel LogLevel = "info"
	// DebugLevel sets logrus level to debug
	DebugLevel LogLevel = "debug"
	// TraceLevel sets logrus level to trace
	TraceLevel LogLevel = "trace"
)

// TLSConfig for the gRPC server's CertFile and KeyFile
type TLSConfig struct {
	CertFile string `json:"certfile,omitempty"`
	KeyFile  string `json:"keyfile,omitempty"`
}

// AuthServerConfig for the gRPC client connection
type AuthServerConfig struct {
	Host string
	Port uint16
}

func (acs AuthServerConfig) String() string {
	return fmt.Sprintf("%s:%d", acs.Host, acs.Port)
}

// ServerConfig is a collection on config
type ServerConfig struct {
	Address       string           `json:"address"`        // HTTP listen Address
	Port          uint16           `json:"port"`           // HTTP listen Port
	ServerAddress string           `json:"server_address"` // Public address of this server
	AdminLTE      string           `json:"adminlte"`       // Path to AdminLTE root
	Templates     string           `json:"templates"`      // Path to template directory
	LogLevel      LogLevel         `json:"loglevel"`       // LogLevel used for logrus
	TLS           *TLSConfig       `json:"tls"`            // TLS will be disabled when nil
	AuthServer    AuthServerConfig `json:"authserver"`     // Config for the gRPC client connection
	LoginURL      string           `json:"login_path"`     // Path to login form
	Audiences     []string         `json:"audiences"`      // Accepted audiences from JWT
	MultiDB       multidb.Config   `json:"multidb"`        // Imported from multidb
	PG            *pg.Config       `json:"pg"`             // PG is later embedded in multidb
	SQLRoutines   int              `json:"sqlroutines"`    // Amount of Go-routines for non-master queries
}

func (c *ServerConfig) writeOut(filename string) error {
	out, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, out, 0644)
}

// Default confing
var Default = ServerConfig{
	Address:       "127.0.0.1",
	Port:          1234,
	ServerAddress: "http://localhost:1234",
	AdminLTE:      "AdminLTE",
	Templates:     "templates",
	LogLevel:      DebugLevel,
	TLS:           nil,
	AuthServer:    AuthServerConfig{"127.0.0.1", 8765},
	LoginURL:      "http://localhost:1235/login",
	MultiDB: multidb.Config{
		StatsLen:      100,
		MaxFails:      10,
		ReconnectWait: 10 * time.Second,
	},
	PG: &pg.Config{
		Nodes: []pg.Node{
			{
				Host: "localhost",
				Port: 5432,
			},
		},
		Params: pg.Params{
			DBname:          "authenticator",
			User:            "postgres",
			Password:        "",
			SSLmode:         "disable",
			Connect_timeout: 30,
		},
	},
	SQLRoutines: 3,
}

var configFiles = flag.String("config", "", "Comma separated list of JSON config files")

func configure(c ServerConfig) (*ServerConfig, error) {
	flag.Parse()

	files := strings.Split(*configFiles, ",")
	s := &c
	for _, f := range files {
		if f == "" {
			continue
		}
		log := log.WithField("file", f)
		js, err := ioutil.ReadFile(f)
		if err != nil {
			log.WithError(err).Error("Read config file")
			return nil, err
		}
		if err = json.Unmarshal(js, s); err != nil {
			log.WithError(err).Error("Unmarshal config file")
			return nil, err
		}
		log.Info("Applied config")
	}

	if s.PG != nil {
		s.MultiDB.DBConf, s.PG = s.PG, nil
	}

	lvl, err := logrus.ParseLevel(string(s.LogLevel))
	if err != nil {
		return nil, err
	}
	log.WithField("level", lvl).Info("Setting log level")
	log.SetLevel(lvl)
	if s.LogLevel == DebugLevel || s.LogLevel == TraceLevel {
		boil.DebugMode = true
	}

	log.WithField("config", *s).Debug("Config loaded")

	return s, nil
}
