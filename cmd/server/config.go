// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"time"

	pb "github.com/moapis/authenticator/pb"
	"github.com/moapis/multidb"
	pg "github.com/moapis/multidb/drivers/postgresql"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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

// ServerConfig is a collection on config
type ServerConfig struct {
	Addres      string         `json:"address"`     // gRPC listen Address
	Port        uint16         `json:"port"`        // gRPC listen Port
	LogLevel    LogLevel       `json:"loglevel"`    // LogLevel used for logrus
	TLS         *TLSConfig     `json:"tls"`         // TLS will be disabled when nil
	MultiDB     multidb.Config `json:"multidb"`     // Imported from multidb
	PG          *pg.Config     `json:"pg"`          // PG is later embedded in multidb
	SQLRoutines int            `json:"sqlroutines"` // Amount of Go-routines for non-master queries
	JWT         JWTConfig      `json:"jwt"`
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
			User:            "postgres",
			Password:        "",
			SSLmode:         "disable",
			Connect_timeout: 30,
		},
	},
	SQLRoutines: 3,
	JWT: JWTConfig{
		Issuer: "localhost",
		Expiry: 24 * time.Hour,
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

func (c ServerConfig) newAuthServer(ctx context.Context, r io.Reader) (*authServer, error) {
	s := &authServer{
		log:  log.WithField("server", "Authenticator"),
		conf: &c,
	}
	var err error
	if s.mdb, err = c.MultiDB.Open(); err != nil {
		return nil, err
	}
	if err = s.updateKeyPair(ctx, r); err != nil {
		return nil, err
	}
	return s, nil
}

func (c ServerConfig) listenAndServe(s *authServer, opts ...grpc.ServerOption) (*grpc.Server, <-chan error) {
	gs := grpc.NewServer(opts...)
	ec := make(chan error)
	pb.RegisterAuthenticatorServer(gs, s)

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
