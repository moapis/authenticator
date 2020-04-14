// Copyright (c) 2020, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func Test_addrString(t *testing.T) {
	type args struct {
		host string
		port uint16
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"Only port",
			args{
				port: 16,
			},
			":16",
		},
		{
			"Address and port",
			args{
				host: "123.123.123.123",
				port: 16,
			},
			"123.123.123.123:16",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := addrString(tt.args.host, tt.args.port); got != tt.want {
				t.Errorf("addrString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthServerConfig_dial(t *testing.T) {
	ectx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()

	type fields struct {
		Host string
		Port uint16
	}
	tests := []struct {
		name    string
		fields  fields
		ctx     context.Context
		wantErr bool
	}{
		{
			"Connection timeout & error",
			fields{
				"1.1.1.1",
				1234,
			},
			ectx,
			true,
		},
		{
			"Sucess",
			fields{
				"localhost",
				8765,
			},
			context.Background(),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &AuthServerConfig{
				Host: tt.fields.Host,
				Port: tt.fields.Port,
			}
			_, err := c.dial(tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthServerConfig.dial() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestServerConfig_writeOut(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{
			"write config",
			"config/defaults.json",
			false,
		},
		{
			"write error",
			"/nowhere/defaults.json",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Default
			if err := c.writeOut(tt.filename); (err != nil) != tt.wantErr {
				t.Errorf("ServerConfig.writeOut() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_configure(t *testing.T) {
	want := Default
	want.Address = "modified"

	type args struct {
		c     *ServerConfig
		files []string
	}
	tests := []struct {
		name    string
		args    args
		want    *ServerConfig
		wantErr bool
	}{
		{
			"No files",
			args{c: &Default},
			&Default,
			false,
		},
		{
			"An empty filename",
			args{
				c:     &Default,
				files: []string{""},
			},
			&Default,
			false,
		},
		{
			"Non existing filename",
			args{
				c:     &Default,
				files: []string{"foobar"},
			},
			nil,
			true,
		},
		{
			"JSON error",
			args{
				c:     &Default,
				files: []string{"tests/error.json"},
			},
			nil,
			true,
		},
		{
			"Applied",
			args{
				c:     &Default,
				files: []string{"tests/modified.json"},
			},
			&want,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := configure(tt.args.c, tt.args.files...)
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
