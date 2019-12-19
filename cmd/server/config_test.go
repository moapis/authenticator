// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/moapis/multidb"
	pg "github.com/moapis/multidb/drivers/postgresql"
)

func TestServerConfig_writeOut(t *testing.T) {
	tests := []struct {
		name     string
		fields   *ServerConfig
		filename string
		wantErr  bool
	}{
		{
			"Write config",
			&Default,
			"./config/defaults.json",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.fields
			if err := c.writeOut(tt.filename); (err != nil) != tt.wantErr {
				t.Errorf("ServerConfig.writeOut() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_configure(t *testing.T) {
	files := map[string][]byte{
		"corrupt.json": []byte("???"),
		"one.json":     []byte("{\"port\": 1}"),
		"two.json":     []byte("{\"port\": 2}"),
	}

	for k, v := range files {
		if err := ioutil.WriteFile(k, v, 0644); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(k)
	}

	tests := []struct {
		name    string
		files   []string
		c       ServerConfig
		want    *ServerConfig
		wantErr bool
	}{
		{
			"File not found",
			[]string{"foobar.json"},
			Default,
			nil,
			true,
		},
		{
			"Corrupt file",
			[]string{"corrupt.json"},
			Default,
			nil,
			true,
		},
		{
			"Multi apply",
			[]string{"one.json", "two.json"},
			ServerConfig{
				Port:     0,
				LogLevel: DebugLevel,
			},
			&ServerConfig{
				Port:     2,
				LogLevel: DebugLevel,
			},
			false,
		},
		{
			"LogLevel error",
			nil,
			ServerConfig{},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			*configFiles = strings.Join(tt.files, ",")
			got, err := configure(tt.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("configure() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("configure() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServerConfig_grpcOpts(t *testing.T) {
	tests := []struct {
		name    string
		tls     *TLSConfig
		wantErr bool
	}{
		{
			"Nil TLS",
			nil,
			false,
		},
		{
			"TLS file errors",
			&TLSConfig{
				"Foo",
				"Bar",
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ServerConfig{TLS: tt.tls}
			got, err := c.grpcOpts()
			if (err != nil) != tt.wantErr {
				t.Errorf("ServerConfig.grpcOpts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("ServerConfig.grpcOpts() = %v, want %v", got, "something")
			}
		})
	}
}

func TestServerConfig_newAuthServer(t *testing.T) {
	ectx, cancel := context.WithTimeout(context.Background(), -1)
	defer cancel()

	cc := *testConfig
	cc.Mail.TemplateGlob = "foo"

	type args struct {
		ctx context.Context
		r   io.Reader
	}
	tests := []struct {
		name    string
		conf    *ServerConfig
		args    args
		wantErr bool
	}{
		{
			"Succesfull",
			testConfig,
			args{testCtx, strings.NewReader(testKeyInput)},
			false,
		},
		{
			"Mdb error",
			&ServerConfig{
				MultiDB: multidb.Config{
					DBConf: pg.Config{
						Nodes: []pg.Node{},
					},
				},
			},
			args{testCtx, strings.NewReader(testKeyInput)},
			true,
		},
		{
			"Expired context",
			testConfig,
			args{ectx, strings.NewReader(testKeyInput)},
			true,
		},
		{
			"Template error",
			&cc,
			args{testCtx, strings.NewReader(testKeyInput)},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.conf.newAuthServer(tt.args.ctx, tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("ServerConfig.newAuthServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("ServerConfig.newAuthServer() = %v, want %v", got, "something")
			}
		})
	}
}

func TestServerConfig_listenAndServe(t *testing.T) {
	type fields struct {
		Addres string
		Port   uint16
	}
	tests := []struct {
		name    string
		fields  fields
		s       *authServer
		wantErr bool
	}{
		{
			"Healthy start",
			fields{
				"127.0.0.1",
				9875,
			},
			tas,
			false,
		},
		{
			"Fail to listen",
			fields{
				"127.0.0.1",
				12,
			},
			tas,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ServerConfig{
				Addres: tt.fields.Addres,
				Port:   tt.fields.Port,
			}
			got, ec := c.listenAndServe(tt.s)
			time.Sleep(time.Millisecond)
			if got == nil {
				t.Errorf("ServerConfig.listen() got = %v, want %v", got, "not nil")
			}
			got.GracefulStop()
			err := <-ec
			if (err != nil) != tt.wantErr {
				t.Errorf("ServerConfig.listen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
