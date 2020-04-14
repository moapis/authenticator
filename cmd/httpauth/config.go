// Copyright (c) 2020, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"time"

	clog "github.com/usrpro/clog15"
	"google.golang.org/grpc"
)

func addrString(host string, port uint16) string {
	return fmt.Sprintf("%s:%d", host, port)
}

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

func (c *AuthServerConfig) dial(ctx context.Context) (cc *grpc.ClientConn, err error) {
	for n := 1; cc == nil; n++ {
		err = ctx.Err()
		if err != nil {
			return nil, fmt.Errorf("authServer dial: %w", err)
		}

		clog.Info(ctx, "authServer dial (re-)trying", "n", n)
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if cc, err = grpc.DialContext(ctx, addrString(c.Host, c.Port), grpc.WithBlock(), grpc.WithInsecure()); err != nil {
			clog.Error(ctx, "authServer dial", "n", n, "err", err)
		}
		cancel()
	}

	clog.Info(ctx, "authServer dial completed")

	return cc, nil
}

// ServerConfig is a collection on config
type ServerConfig struct {
	Address       string                 `json:"address"`        // HTTP listen Address
	Port          uint16                 `json:"port"`           // HTTP listen Port
	Timeout       time.Duration          `json:"timeout"`        // HTTP read and write timeouts
	ServerAddress string                 `json:"server_address"` // Public address of this server
	Static        string                 `json:"static"`         // Path to static assets
	TemplateGlob  string                 `json:"template_glob"`  // Globbing pattern for templates
	Data          map[string]interface{} `json:"data"`           // Static data passed to the templates
	TLS           *TLSConfig             `json:"tls"`            // TLS will be disabled when nil
	AuthServer    AuthServerConfig       `json:"authserver"`     // Config for the gRPC client connection
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
	Port:          1235,
	Timeout:       10 * time.Second,
	ServerAddress: "http://localhost:1235",
	Data: map[string]interface{}{
		"SiteName": "Authenticator",
	},
	Static:       "static",
	TemplateGlob: "templates/*.html",
	TLS:          nil,
	AuthServer:   AuthServerConfig{"127.0.0.1", 8765},
}

func configure(c *ServerConfig, files ...string) (*ServerConfig, error) {
	flag.Parse()

	s := *c
	for _, f := range files {
		if f == "" {
			continue
		}
		js, err := ioutil.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(js, &s); err != nil {
			return nil, err
		}
	}

	// TODO: loglevel

	return &s, nil
}
