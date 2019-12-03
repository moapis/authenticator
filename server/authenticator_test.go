// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/moapis/authenticator/models"
	"github.com/moapis/multidb"
	"github.com/spf13/viper"
)

const (
	testKeyInput = "qwertyuiopasdfghjklzxcvbnm123456"
	testPrivKey  = "qwertyuiopasdfghjklzxcvbnm123456\xda\xf9W\x14\xfcc\xe2\xe5\x1b+i\xa3\n\xbek($\x1e\x18\xc6j/*\x88\xaf\xa7X݉|ֳ"
	testPubKey   = "\xda\xf9W\x14\xfcc\xe2\xe5\x1b+i\xa3\n\xbek($\x1e\x18\xc6j/*\x88\xaf\xa7X݉|ֳ"
)

func Test_authServer_updateKeyPair(t *testing.T) {
	errMDB := new(multidb.MultiDB)
	type fields struct {
		mdb *multidb.MultiDB
	}
	type result struct {
		privKey privateKey
		pubKey  ed25519.PublicKey
	}
	type args struct {
		ctx context.Context
		r   io.Reader
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    result
		wantErr bool
	}{
		{
			name: "Defined input reader",
			fields: fields{
				mdb: mdb,
			},
			args: args{
				testCtx,
				strings.NewReader(testKeyInput),
			},
			want: result{
				privKey: privateKey{
					id:  "1",
					key: []byte(testPrivKey),
				},
				pubKey: []byte(testPubKey),
			},
		},
		{
			name: "Defunct input reader",
			fields: fields{
				mdb: mdb,
			},
			args: args{
				testCtx,
				strings.NewReader(""),
			},
			wantErr: true,
		},
		{
			name: "DB error",
			fields: fields{
				mdb: errMDB,
			},
			args: args{
				testCtx,
				strings.NewReader(testKeyInput),
			},
			wantErr: true,
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &authServer{
				mdb: tt.fields.mdb,
			}
			err := s.updateKeyPair(tt.args.ctx, tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.updateKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got := result{
				privKey: s.privKey,
			}
			if !tt.wantErr {
				n, err := mdb.Node()
				if err != nil {
					t.Fatal(err)
				}
				m, err := models.FindJWTKey(testCtx, n, i+1, "public_key")
				if err != nil {
					t.Fatal(err)
				}
				got.pubKey = m.PublicKey
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authServer.updateKeyPair() = \n%v\nwant\n %v", got, tt.want)
			}
			s.keyMtx.Lock() // Will hang if mutex was not proberly cleared
			s.keyMtx.Unlock()
		})
	}
}

func Test_newAuthServer(t *testing.T) {
	s, err := newAuthServer(context.Background(), rand.Reader)
	if err != nil {
		t.Errorf("newAuthServer() error = %v, wantErr %v", err, false)
	}
	if s == nil {
		t.Errorf("newAuthServer() = %v, want %v", s, &authServer{})
	}

	oldLvl := viper.GetString("LogLevel")
	viper.Set("LogLevel", "Foobar")
	s, err = newAuthServer(context.Background(), rand.Reader)
	if err == nil {
		t.Errorf("newAuthServer() error = %v, wantErr %v", err, true)
	}
	if s != nil {
		t.Errorf("newAuthServer() = %v, want %v", s, nil)
	}
	viper.Set("LogLevel", oldLvl)

	oldHm := viper.Get("DBHosts").(map[string]uint16)
	viper.Set("DBHosts", make(map[string]uint16))
	s, err = newAuthServer(context.Background(), rand.Reader)
	if err == nil {
		t.Errorf("newAuthServer() error = %v, wantErr %v", err, true)
	}
	if s != nil {
		t.Errorf("newAuthServer() = %v, want %v", s, nil)
	}
	viper.Set("DBHosts", oldHm)

	s, err = newAuthServer(context.Background(), strings.NewReader(""))
	if err == nil {
		t.Errorf("newAuthServer() error = %v, wantErr %v", err, true)
	}
	if s != nil {
		t.Errorf("newAuthServer() = %v, want %v", s, nil)
	}
}

func Test_authServer_privateKey(t *testing.T) {
	type fields struct {
		privKey privateKey
	}
	tests := []struct {
		name   string
		fields fields
		want   privateKey
	}{
		{
			name: "Empty key",
		},
		{
			name: "Predefined key",
			fields: fields{
				privKey: privateKey{
					id:  "foo",
					key: []byte(testPrivKey),
				},
			},
			want: privateKey{
				id:  "foo",
				key: []byte(testPrivKey),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &authServer{
				privKey: tt.fields.privKey,
			}
			if got := s.privateKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authServer.privateKey() = %v, want %v", got, tt.want)
			}
			s.keyMtx.Lock() // Will hang if mutex was not proberly cleared
			s.keyMtx.Unlock()
		})
	}
}
