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
	"time"

	"github.com/moapis/authenticator/models"
	pb "github.com/moapis/authenticator/pb"
	"github.com/moapis/multidb"
	"github.com/pascaldekloe/jwt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	testKeyInput = "qwertyuiopasdfghjklzxcvbnm123456"
	testPrivKey  = "qwertyuiopasdfghjklzxcvbnm123456\xda\xf9W\x14\xfcc\xe2\xe5\x1b+i\xa3\n\xbek($\x1e\x18\xc6j/*\x88\xaf\xa7X݉|ֳ"
	testPubKey   = "\xda\xf9W\x14\xfcc\xe2\xe5\x1b+i\xa3\n\xbek($\x1e\x18\xc6j/*\x88\xaf\xa7X݉|ֳ"
)

var (
	testPrivateKey = privateKey{
		id:  "10",
		key: []byte(testPrivKey),
	}
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

func Test_authServer_RegisterPwUser(t *testing.T) {
	exCtx, cancel := context.WithTimeout(testCtx, -1)
	defer cancel()

	type args struct {
		ctx context.Context
		pu  *pb.NewPwUser
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"Expired context",
			args{
				exCtx,
				nil,
			},
			true,
		},
		{
			"Empty user",
			args{
				testCtx,
				&pb.NewPwUser{},
			},
			true,
		},
		{
			"Valid user",
			args{
				testCtx,
				&pb.NewPwUser{
					Email:    "hello@world.com",
					Name:     "hello",
					Password: "something",
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &authServer{
				mdb:     mdb,
				privKey: testPrivateKey,
				log:     logrus.NewEntry(log),
			}
			got, err := s.RegisterPwUser(tt.args.ctx, tt.args.pu)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.RegisterPwUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("authServer.RegisterPwUser() = %v, wantErr %v", got, tt.wantErr)
			}
		})
	}
}

func Test_authServer_AuthenticatePwUser(t *testing.T) {
	exCtx, cancel := context.WithTimeout(testCtx, -1)
	defer cancel()

	type args struct {
		ctx context.Context
		up  *pb.UserPassword
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"Expired context",
			args{
				exCtx,
				nil,
			},
			true,
		},
		{
			"Empty user",
			args{
				testCtx,
				&pb.UserPassword{},
			},
			true,
		},
		{
			"Valid user and passwd",
			args{
				testCtx,
				&pb.UserPassword{
					User:     &pb.UserPassword_Email{Email: "one@group.com"},
					Password: "oneGroup",
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &authServer{
				mdb:     mdb,
				privKey: testPrivateKey,
				log:     logrus.NewEntry(log),
			}
			got, err := s.AuthenticatePwUser(tt.args.ctx, tt.args.up)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.AuthenticatePwUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("authServer.AuthenticatePwUser() = %v, wantErr %v", got, tt.wantErr)
			}
		})
	}
}

func Test_authServer_ChangeUserPw(t *testing.T) {
	exCtx, cancel := context.WithTimeout(testCtx, -1)
	defer cancel()

	type args struct {
		ctx context.Context
		up  *pb.NewUserPassword
	}
	tests := []struct {
		name    string
		args    args
		want    *pb.ChangePwReply
		wantErr bool
	}{
		{
			"Expired context",
			args{
				exCtx,
				nil,
			},
			nil,
			true,
		},
		{
			"Empty user",
			args{
				testCtx,
				&pb.NewUserPassword{},
			},
			nil,
			true,
		},
		{
			"Valid user and passwd",
			args{
				testCtx,
				&pb.NewUserPassword{
					User:        &pb.NewUserPassword_Email{Email: "one@group.com"},
					Credential:  &pb.NewUserPassword_OldPassword{OldPassword: "oneGroup"},
					NewPassword: "oneGroup",
				},
			},
			&pb.ChangePwReply{Success: true},
			false,
		},
		{
			"Empty new passwd",
			args{
				testCtx,
				&pb.NewUserPassword{
					User:        &pb.NewUserPassword_Email{Email: "one@group.com"},
					Credential:  &pb.NewUserPassword_OldPassword{OldPassword: "oneGroup"},
					NewPassword: "",
				},
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &authServer{
				mdb:     mdb,
				privKey: testPrivateKey,
				log:     logrus.NewEntry(log),
			}
			got, err := s.ChangeUserPw(tt.args.ctx, tt.args.up)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.ChangeUserPw() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authServer.ChangeUserPw() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authServer_CheckUserExists(t *testing.T) {
	exCtx, cancel := context.WithTimeout(testCtx, -1)
	defer cancel()

	type args struct {
		ctx context.Context
		ud  *pb.UserData
	}
	tests := []struct {
		name    string
		args    args
		want    *pb.Exists
		wantErr bool
	}{
		{
			"Expired context",
			args{
				exCtx,
				nil,
			},
			nil,
			true,
		},
		{
			"Empty user",
			args{
				testCtx,
				&pb.UserData{},
			},
			nil,
			true,
		},
		{
			"Existing name",
			args{
				testCtx,
				&pb.UserData{Name: "oneGroup"},
			},
			&pb.Exists{Name: true},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &authServer{
				mdb:     mdb,
				privKey: testPrivateKey,
				log:     logrus.NewEntry(log),
			}
			got, err := s.CheckUserExists(tt.args.ctx, tt.args.ud)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.CheckUserExists() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authServer.CheckUserExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authServer_RefreshToken(t *testing.T) {
	exCtx, cancel := context.WithTimeout(testCtx, -1)
	defer cancel()

	claims := &jwt.Claims{
		KeyID: "10",
		Registered: jwt.Registered{
			Issuer:    viper.GetString("JWTIssuer"),
			Subject:   testUsers["allGroups"].Name,
			Expires:   jwt.NewNumericTime(time.Now().Add(viper.GetDuration("JWTExpiry"))),
			Audiences: []string{"me", "and", "you"},
			Issued:    jwt.NewNumericTime(time.Now()),
		},
		Set: map[string]interface{}{
			"user_id":   103,
			"group_ids": []int{1, 2, 3},
		},
	}
	jwtKnown, err := claims.EdDSASign([]byte(testPrivKey))
	if err != nil {
		t.Fatal(err)
	}

	claims = &jwt.Claims{
		KeyID: "10",
		Registered: jwt.Registered{
			Issuer:    viper.GetString("JWTIssuer"),
			Subject:   "Nobody",
			Expires:   jwt.NewNumericTime(time.Now().Add(viper.GetDuration("JWTExpiry"))),
			Audiences: []string{"me", "and", "you"},
			Issued:    jwt.NewNumericTime(time.Now()),
		},
		Set: map[string]interface{}{
			"user_id":   667,
			"group_ids": []int{1, 2, 3},
		},
	}
	jwtUnKnown, err := claims.EdDSASign([]byte(testPrivKey))
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		ctx context.Context
		old *pb.AuthReply
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"Expired context",
			args{
				exCtx,
				nil,
			},
			true,
		},
		{
			"Empty token",
			args{
				testCtx,
				&pb.AuthReply{},
			},
			true,
		},
		{
			"Known User",
			args{
				testCtx,
				&pb.AuthReply{Jwt: string(jwtKnown)},
			},
			false,
		},
		{
			"Unknown User",
			args{
				testCtx,
				&pb.AuthReply{Jwt: string(jwtUnKnown)},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &authServer{
				mdb:     mdb,
				privKey: testPrivateKey,
				log:     logrus.NewEntry(log),
			}
			got, err := s.RefreshToken(tt.args.ctx, tt.args.old)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.RefreshToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("authServer.RefreshToken() = %v, wantErr %v", got, tt.wantErr)
			}
		})
	}
}

func Test_authServer_PublicUserToken(t *testing.T) {
	exCtx, cancel := context.WithTimeout(testCtx, -1)
	defer cancel()

	type args struct {
		ctx context.Context
		pu  *pb.PublicUser
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"Expired context",
			args{
				exCtx,
				nil,
			},
			true,
		},
		{
			"Empty uuid",
			args{
				testCtx,
				&pb.PublicUser{},
			},
			true,
		},
		{
			"Valid uuid",
			args{
				testCtx,
				&pb.PublicUser{Uuid: "somethingRndm"},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &authServer{
				mdb:     mdb,
				privKey: testPrivateKey,
				log:     logrus.NewEntry(log),
			}
			got, err := s.PublicUserToken(tt.args.ctx, tt.args.pu)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.PublicUserToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("authServer.PublicUserToken() = %v, wantErr %v", got, tt.wantErr)
			}
		})
	}
}

func Test_authServer_GetPubKey(t *testing.T) {
	exCtx, cancel := context.WithTimeout(testCtx, -1)
	defer cancel()

	type args struct {
		ctx context.Context
		k   *pb.KeyID
	}
	tests := []struct {
		name    string
		args    args
		want    *pb.PublicKey
		wantErr bool
	}{
		{
			"Expired context",
			args{
				exCtx,
				nil,
			},
			nil,
			true,
		},
		{
			"Empty Kid",
			args{
				testCtx,
				&pb.KeyID{},
			},
			nil,
			true,
		},
		{
			"Known Kid",
			args{
				testCtx,
				&pb.KeyID{Kid: 10},
			},
			&pb.PublicKey{Key: []byte(testPubKey)},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &authServer{
				mdb:     mdb,
				privKey: testPrivateKey,
				log:     logrus.NewEntry(log),
			}
			got, err := s.GetPubKey(tt.args.ctx, tt.args.k)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.GetPubKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authServer.GetPubKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
