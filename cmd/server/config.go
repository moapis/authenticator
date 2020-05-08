// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net"
	"net/smtp"
	"strings"
	"time"

	auth "github.com/moapis/authenticator"
	"github.com/moapis/authenticator/models"
	"github.com/moapis/mailer"
	"github.com/moapis/multidb"
	pg "github.com/moapis/multidb/drivers/postgresql"
	"github.com/sirupsen/logrus"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"golang.org/x/crypto/argon2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// TLSConfig for the gRPC server's CertFile and KeyFile
type TLSConfig struct {
	CertFile string `json:"certfile,omitempty"`
	KeyFile  string `json:"keyfile,omitempty"`
}

// JWTConfig sets static properties of every token produced by this server
type JWTConfig struct {
	Issuer string        `json:"issuer,omitempty"`
	Expiry time.Duration `json:"expiry,omitempty"`
}

// BootstrapUser defines a primary user
type BootstrapUser struct {
	Email     string
	Name      string
	Password  string
	Groups    []string
	Audiences []string
}

// MailConfig for outgoing mail server
type MailConfig struct {
	Host         string
	Port         uint16
	Identity     string
	Username     string
	Password     string
	From         string
	TemplateGlob string
}

// ServerConfig is a collection on config
type ServerConfig struct {
	Addres      string          `json:"address"`     // gRPC listen Address
	Port        uint16          `json:"port"`        // gRPC listen Port
	LogLevel    LogLevel        `json:"loglevel"`    // LogLevel used for logrus
	TLS         *TLSConfig      `json:"tls"`         // TLS will be disabled when nil
	MultiDB     multidb.Config  `json:"multidb"`     // Imported from multidb
	PG          *pg.Config      `json:"pg"`          // PG is later embedded in multidb
	SQLRoutines int             `json:"sqlroutines"` // Amount of Go-routines for non-master queries
	Users       []BootstrapUser `json:"bootsrap"`    // Users which will be upserted at start
	JWT         JWTConfig       `json:"jwt"`
	Mail        MailConfig      `json:"smtp"`
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
	Addres:   "127.0.0.1",
	Port:     8765,
	LogLevel: InfoLevel,
	TLS:      nil,
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
			DBname:          "authenticator_test",
			User:            "authenticator",
			Password:        "default",
			SSLmode:         "disable",
			Connect_timeout: 30,
		},
	},
	SQLRoutines: 3,
	Users: []BootstrapUser{
		{
			Name:      "admin",
			Email:     "admin@localhost",
			Password:  "admin",
			Groups:    []string{"primary"},
			Audiences: []string{"authenticator"},
		},
	},
	JWT: JWTConfig{
		Issuer: "localhost",
		Expiry: 24 * time.Hour,
	},
	Mail: MailConfig{
		Host:         "test.mailu.io",
		Port:         587,
		Identity:     "",
		Username:     "admin@test.mailu.io",
		Password:     "letmein",
		From:         "admin@test.mailu.io",
		TemplateGlob: "templates/*.mail.html",
	},
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

	log.WithField("config", *s).Debug("Config loaded")

	return s, nil
}

func (c ServerConfig) grpcOpts() ([]grpc.ServerOption, error) {
	opts := []grpc.ServerOption{
		grpc.UnaryInterceptor(middlewareInterceptor),
	}
	if c.TLS != nil {
		log := log.WithFields(logrus.Fields{"certFile": c.TLS.CertFile, "keyFile": c.TLS.KeyFile})
		cert, err := tls.LoadX509KeyPair(c.TLS.CertFile, c.TLS.KeyFile)
		if err != nil {
			log.WithError(err).Error("Failed to set TLS opts")
			return nil, err
		}
		opts = append(opts, grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	}
	return opts, nil
}

func (c ServerConfig) bootStrapUsers(ctx context.Context, s *authServer) error {
	for _, u := range c.Users {
		tx, err := s.mdb.MasterTx(ctx, nil)
		if err != nil {
			log.WithError(err).Error("bootstrapUsers")
			return err
		}
		defer tx.Rollback()

		log := s.log.WithField("user", u)
		um := &models.User{
			Name:  u.Name,
			Email: u.Email,
		}
		if err = um.Insert(ctx, tx, boil.Infer()); err != nil {
			if strings.Contains(err.Error(), "pq: duplicate key value violates unique constraint") {
				log.WithError(err).Info("user exists")
				continue
			}
			log.WithError(err).Error("bootstrap User insert")
			return err
		}
		log.Debug("bootstrap User insert")

		pwm := &models.Password{
			UserID: um.ID,
			Salt:   make([]byte, PasswordSaltLen),
		}
		if _, err := rand.Read(pwm.Salt); err != nil {
			log.WithError(err).Error("Salt generation")
			return status.Error(codes.Internal, errFatal)
		}
		pwm.Hash = argon2.IDKey([]byte(u.Password), pwm.Salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
		log = log.WithField("password_model", pwm)

		if err := um.SetPassword(ctx, tx, true, pwm); err != nil {
			log.WithError(err).Error("password.SetPassword()")
			return status.Error(codes.Internal, errDB)
		}
		log.Debug("bootstrap password Upsert()")

		gms := make([]*models.Group, len(u.Groups))
		for i, g := range u.Groups {
			gms[i] = &models.Group{Name: g}
		}
		if err = um.SetGroups(ctx, tx, true, gms...); err != nil {
			log.WithError(err).Error("bootstrap SetGroups")
			return err
		}
		log.Debug("bootstrap SetGroups")

		ams := make([]*models.Audience, len(u.Audiences))
		for i, a := range u.Audiences {
			ams[i] = &models.Audience{Name: a}
		}
		if err = um.SetAudiences(ctx, tx, true, ams...); err != nil {
			log.WithError(err).Error("bootstrap SetAudiences")
			return err
		}
		log.Debug("bootstrap SetAudiences")

		if err = tx.Commit(); err != nil {
			log.WithError(err).Error("bootstrap commit")
			return err
		}
		log.Debug("bootstrap commit")
	}
	return nil
}

func (c ServerConfig) newAuthServer(ctx context.Context, r io.Reader) (*authServer, error) {
	s := &authServer{
		log:  log.WithField("server", "Authenticator"),
		conf: &c,
	}
	var err error
	if s.mdb, err = c.MultiDB.Open(); err != nil {
		return nil, err
	}

	if err = c.bootStrapUsers(ctx, s); err != nil {
		return nil, err
	}

	if err = s.updateKeyPair(ctx, r); err != nil {
		return nil, err
	}

	tmpl, err := template.ParseGlob(c.Mail.TemplateGlob)
	if err != nil {
		return nil, err
	}
	s.mail = mailer.New(
		tmpl,
		fmt.Sprintf("%s:%d", c.Mail.Host, c.Mail.Port),
		c.Mail.From,
		smtp.PlainAuth(c.Mail.Identity, c.Mail.Username, c.Mail.Password, c.Mail.Host),
	)
	return s, nil
}

func (c ServerConfig) listenAndServe(s *authServer, opts ...grpc.ServerOption) (*grpc.Server, <-chan error) {
	gs := grpc.NewServer(opts...)
	ec := make(chan error)
	auth.RegisterAuthenticatorServer(gs, s)

	log := log.WithFields(logrus.Fields{"address": c.Addres, "port": c.Port})
	log.WithField("grpc", gs.GetServiceInfo()).Debug("Registered services")
	log.Info("Starting server")

	go func(ec chan<- error) {
		lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.Addres, c.Port))
		if err != nil {
			log.WithError(err).Error("Failed to listen")
			ec <- err
			return
		}
		if err = gs.Serve(lis); err != nil {
			log.WithError(err).Error("Failed to serve")
			ec <- err
			return
		}
		ec <- nil
	}(ec)
	return gs, ec
}
