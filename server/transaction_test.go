// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/friendsofgo/errors"
	"github.com/moapis/authenticator/models"
	pb "github.com/moapis/authenticator/pb"
	"github.com/moapis/multidb"
	"github.com/pascaldekloe/jwt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/argon2"
)

func Test_authServer_newTx(t *testing.T) {
	ex, cancel := context.WithTimeout(context.Background(), -1)
	defer cancel()
	type fields struct {
		mdb *multidb.MultiDB
		log *logrus.Entry
	}
	type args struct {
		ctx    context.Context
		method string
		master bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			"Slave node",
			fields{
				mdb: mdb,
				log: logrus.NewEntry(log),
			},
			args{
				ctx:    context.Background(),
				method: "some",
				master: false,
			},
			false,
		},
		{
			"Master node",
			fields{
				mdb: mdb,
				log: logrus.NewEntry(log),
			},
			args{
				ctx:    context.Background(),
				method: "some",
				master: true,
			},
			false,
		},
		{
			"Context error",
			fields{
				mdb: mdb,
				log: logrus.NewEntry(log),
			},
			args{
				ctx:    ex,
				method: "some",
				master: false,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &authServer{
				mdb: tt.fields.mdb,
				log: tt.fields.log,
			}
			got, err := s.newTx(tt.args.ctx, tt.args.method, tt.args.master)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.newTx() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && (got == nil || got.tx == nil || got.ctx == nil || got.cancel == nil || got.log == nil || got.s == nil) {
				t.Errorf("authServer.newTx() = %v, unexpected nil field", got)
			}
			if !tt.wantErr {
				if err = got.commit(); err != nil {
					t.Fatal(err)
				}
				got.done()
			}
		})
	}
}

func Test_requestTx_enoughTime(t *testing.T) {
	ex, cancel := context.WithTimeout(context.Background(), -1)
	defer cancel()
	short, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tests := []struct {
		name    string
		ctx     context.Context
		need    time.Duration
		wantErr bool
	}{
		{
			"Expired context",
			ex,
			0,
			true,
		},
		{
			"Enough time",
			short,
			time.Millisecond,
			false,
		},
		{
			"Skip check",
			short,
			time.Millisecond,
			false,
		},
		{
			"Not enough time",
			short,
			2 * time.Second,
			true,
		},
		{
			"No deadline",
			context.Background(),
			time.Millisecond,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &requestTx{
				ctx: tt.ctx,
				log: logrus.NewEntry(log),
			}
			if err := rt.enoughTime(tt.need); (err != nil) != tt.wantErr {
				t.Errorf("requestTx.enoughTime() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func newTestTx() (*requestTx, error) {
	s := &authServer{
		mdb: mdb,
		log: logrus.NewEntry(log),
		privKey: privateKey{
			id:  "10",
			key: []byte(testPrivKey),
		},
	}
	return s.newTx(context.Background(), "testing", false)
}

func Test_requestTx_done_commit(t *testing.T) {
	tx, err := newTestTx()
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.commit(); err != nil {
		t.Errorf("requestTx.commit() error = %v, wantErr %v", err, false)
	}
	if err = tx.commit(); err == nil {
		t.Errorf("requestTx.commit() error = %v, wantErr %v", err, true)
	}
	tx.done()
	tx, err = newTestTx()
	if err != nil {
		t.Fatal(err)
	}
	tx.done()
}

func Test_requestTx_authReply(t *testing.T) {
	type args struct {
		subject   string
		issued    time.Time
		set       map[string]interface{}
		audiences []string
	}
	tests := []struct {
		name    string
		args    args
		want    *pb.AuthReply
		wantErr bool
	}{
		{
			"Fixed key/time",
			args{
				subject:   "testuser",
				issued:    time.Unix(123, 456),
				set:       map[string]interface{}{"some": 1},
				audiences: []string{"foo", "bar"},
			},
			&pb.AuthReply{
				Jwt: "eyJhbGciOiJFZERTQSIsImtpZCI6IjEwIn0.eyJhdWQiOlsiZm9vIiwiYmFyIl0sImV4cCI6ODY1MjMuMDAwMDAwNDU2LCJpYXQiOjEyMy4wMDAwMDA0NTYsImlzcyI6ImxvY2FsaG9zdCIsInNvbWUiOjEsInN1YiI6InRlc3R1c2VyIn0.Ox2PHwJ5Q7u4P2n5y1PZ630hm0J0N4yam14GA4-NSgn-Ak3L9Au2a8GHzN-AoQGbREJA1GDdIwGWIoGS3TthBQ",
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := newTestTx()
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()
			got, err := rt.authReply(tt.args.subject, tt.args.issued, tt.args.set, tt.args.audiences...)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestTx.authReply() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("requestTx.authReply() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_requestTx_userAuthReply(t *testing.T) {
	type args struct {
		user      *models.User
		issued    time.Time
		audiences []string
	}
	tests := []struct {
		name    string
		args    args
		want    *pb.AuthReply
		wantErr bool
	}{
		{
			"No group",
			args{
				testUsers["noGroup"],
				time.Unix(123, 456),
				nil,
			},
			&pb.AuthReply{
				Jwt: "eyJhbGciOiJFZERTQSIsImtpZCI6IjEwIn0.eyJleHAiOjg2NTIzLjAwMDAwMDQ1NiwiZ3JvdXBfaWRzIjpbXSwiaWF0IjoxMjMuMDAwMDAwNDU2LCJpc3MiOiJsb2NhbGhvc3QiLCJzdWIiOiJub0dyb3VwIiwidXNlcl9pZCI6MTAxfQ.cN5J_jiwdE25scA3p1X2BgAeMxYtLLYwORF7kOPgbDEnegspSyxPLnklOf46QG1-wsN3Ju8sWH134palAGTBAQ",
			},
			false,
		},
		{
			"One group",
			args{
				testUsers["oneGroup"],
				time.Unix(123, 456),
				nil,
			},
			&pb.AuthReply{
				Jwt: "eyJhbGciOiJFZERTQSIsImtpZCI6IjEwIn0.eyJleHAiOjg2NTIzLjAwMDAwMDQ1NiwiZ3JvdXBfaWRzIjpbMV0sImlhdCI6MTIzLjAwMDAwMDQ1NiwiaXNzIjoibG9jYWxob3N0Iiwic3ViIjoib25lR3JvdXAiLCJ1c2VyX2lkIjoxMDJ9.gbkjDYNFamC2AJEIU-HlMzh1mHLeYdm8dv8an60Z2nvHuhKXUY7RCzMARUtrXeEuYDAaiSWYwqXN4AyWDzoJAw",
			},
			false,
		},
		{
			"All groups",
			args{
				testUsers["allGroups"],
				time.Unix(123, 456),
				[]string{"me", "and", "you"},
			},
			&pb.AuthReply{
				Jwt: "eyJhbGciOiJFZERTQSIsImtpZCI6IjEwIn0.eyJhdWQiOlsibWUiLCJhbmQiLCJ5b3UiXSwiZXhwIjo4NjUyMy4wMDAwMDA0NTYsImdyb3VwX2lkcyI6WzEsMiwzXSwiaWF0IjoxMjMuMDAwMDAwNDU2LCJpc3MiOiJsb2NhbGhvc3QiLCJzdWIiOiJhbGxHcm91cHMiLCJ1c2VyX2lkIjoxMDN9.j0hyUeEUu8ZKFl8n4s-8HFzC5eR4Y5KjT5vI2dHNCu-MRdz2iB0Dh2C2EqZ_sILggtkTTjtrScRxTOlcX8kgBA",
			},
			false,
		},
		{
			"Error",
			args{
				testUsers["allGroups"],
				time.Unix(123, 456),
				nil,
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := newTestTx()
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()
			if tt.wantErr {
				rt.done()
			}
			got, err := rt.userAuthReply(tt.args.user, tt.args.issued, tt.args.audiences...)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestTx.userAuthReply() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("requestTx.userAuthReply() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_requestTx_findJWTKey(t *testing.T) {
	tests := []struct {
		name    string
		kid     int
		want    []byte
		wantErr bool
	}{
		{
			"Missing Key ID",
			0,
			nil,
			true,
		},
		{
			"Existing Key ID",
			10,
			[]byte(testPubKey),
			false,
		},
		{
			"Key not found",
			22,
			nil,
			true,
		},
		{
			"DB error",
			22,
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := newTestTx()
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()
			if tt.name == "DB error" {
				rt.done()
			}
			got, err := rt.findJWTKey(tt.kid)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestTx.findJWTKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("requestTx.findJWTKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_requestTx_checkJWT(t *testing.T) {
	c := &jwt.Claims{
		KeyID: "66",
	}
	neid, err := c.EdDSASign([]byte(testPrivKey))
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		token string
		valid time.Time
	}
	tests := []struct {
		name    string
		args    args
		want    *jwt.Claims
		wantErr bool
	}{
		{
			"Expired JWT",
			args{
				"eyJhbGciOiJFZERTQSIsImtpZCI6IjEwIn0.eyJleHAiOjg2NTIzLjAwMDAwMDQ1NiwiZ3JvdXBfaWRzIjpbXSwiaWF0IjoxMjMuMDAwMDAwNDU2LCJpc3MiOiJsb2NhbGhvc3QiLCJzdWIiOiJub0dyb3VwIiwidXNlcl9pZCI6MTAxfQ.cN5J_jiwdE25scA3p1X2BgAeMxYtLLYwORF7kOPgbDEnegspSyxPLnklOf46QG1-wsN3Ju8sWH134palAGTBAQ",
				time.Now(),
			},
			nil,
			true,
		},
		{
			"Valid JWT",
			args{
				"eyJhbGciOiJFZERTQSIsImtpZCI6IjEwIn0.eyJhdWQiOlsibWUiLCJhbmQiLCJ5b3UiXSwiZXhwIjo4NjUyMy4wMDAwMDA0NTYsImdyb3VwX2lkcyI6WzEsMiwzXSwiaWF0IjoxMjMuMDAwMDAwNDU2LCJpc3MiOiJsb2NhbGhvc3QiLCJzdWIiOiJhbGxHcm91cHMiLCJ1c2VyX2lkIjoxMDN9.j0hyUeEUu8ZKFl8n4s-8HFzC5eR4Y5KjT5vI2dHNCu-MRdz2iB0Dh2C2EqZ_sILggtkTTjtrScRxTOlcX8kgBA",
				time.Unix(124, 0),
			},
			&jwt.Claims{
				Registered: jwt.Registered{
					Issuer:    viper.GetString("JWTIssuer"),
					Subject:   testUsers["allGroups"].Name,
					Expires:   jwt.NewNumericTime(time.Unix(123, 456).Add(viper.GetDuration("JWTExpiry"))),
					Audiences: []string{"me", "and", "you"},
					Issued:    jwt.NewNumericTime(time.Unix(123, 456)),
				},
				Set: map[string]interface{}{
					"user_id":   103,
					"group_ids": []int{1, 2, 3},
				},
			},
			false,
		},
		{
			"Empty token",
			args{
				"",
				time.Now(),
			},
			nil,
			true,
		},
		{
			"Malformed token header",
			args{
				"foobar",
				time.Now(),
			},
			nil,
			true,
		},
		{
			"Non-existing ID",
			args{
				string(neid),
				time.Now(),
			},
			nil,
			true,
		},
		{
			"Malformed token signature",
			args{
				"eyJhbGciOiJFZERTQSIsImtpZCI6IjEwIn0.eyJhdWQiOlsibWUiLCJhbmQiLCJ5b3UiXSwiZXhwIjo4NjUyMy4wMDAwMDA0NTYsImdyb3VwX2lkcyI6WzEsMiwzXSwiaWF0IjoxMjMuMDAwMDAwNDU2LCJpc3MiOiJsb2NhbGhvc3QiLCJzdWIiOiJhbGxHcm91cHMiLCJ1c2VyX2lkIjoxMDN9.foobar",
				time.Unix(124, 0),
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := newTestTx()
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()
			if tt.want != nil {
				tt.want.KeyID = rt.s.privateKey().id
			}
			got, err := rt.checkJWT(tt.args.token, tt.args.valid)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestTx.checkJWT() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.want == got {
				return
			}
			if tt.want != nil && got == nil {
				t.Errorf("requestTx.checkJWT() = %v, want %v", got, tt.want)
				return
			}
			if !reflect.DeepEqual(got.Registered, tt.want.Registered) {
				t.Errorf("requestTx.checkJWT() = %v, want %v", got.Registered, tt.want.Registered)
			}
			if fmt.Sprint(got.Set) != fmt.Sprint(tt.want.Set) {
				t.Errorf("requestTx.checkJWT() = %v, want %v", got.Set, tt.want.Set)
			}
		})
	}
}

func Test_requestTx_setUserPassword(t *testing.T) {
	type args struct {
		user     *models.User
		password string
		read     func([]byte) (int, error)
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"Empty password",
			args{
				&models.User{},
				"",
				rand.Read,
			},
			true,
		},
		{
			"Read error",
			args{
				&models.User{},
				"Somepass",
				func([]byte) (int, error) { return 0, errors.New("SomeErr") },
			},
			true,
		},
		{
			"SetPassword error",
			args{
				&models.User{},
				"Somepass",
				rand.Read,
			},
			true,
		},
		{
			"Success",
			args{
				testUsers["allGroups"],
				"Somepass",
				rand.Read,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := newTestTx()
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()
			if err := rt.setUserPassword(tt.args.user, tt.args.password, tt.args.read); (err != nil) != tt.wantErr {
				t.Errorf("requestTx.setUserPassword() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				pw, err := tt.args.user.Password().One(testCtx, rt.tx)
				if err != nil {
					t.Fatal(err)
				}
				t.Log(pw)
				exp := argon2.IDKey([]byte(tt.args.password), pw.Salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
				if !reflect.DeepEqual(exp, pw.Hash) {
					t.Errorf("requestTx.setUserPassword() = %v, want %v", string(pw.Hash), string(exp))
				}
			}
		})
	}
}

func Test_requestTx_insertPwUser(t *testing.T) {
	type args struct {
		email    string
		name     string
		password string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"Empty email",
			args{
				"",
				"foo",
				"pass",
			},
			true,
		},
		{
			"Success",
			args{
				"foo@bar.com",
				"foo",
				"pass",
			},
			false,
		},
		{
			"Duplicate",
			args{
				"foo@bar.com",
				"foo",
				"pass",
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := newTestTx()
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()
			want, err := rt.insertPwUser(tt.args.email, tt.args.name, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestTx.insertPwUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			got, err := models.FindUser(testCtx, rt.tx, want.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Email != want.Email {
				t.Errorf("requestTx.insertPwUser() = %v, want %v", got, want)
			}
			if err := rt.commit(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
