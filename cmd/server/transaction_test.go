// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/friendsofgo/errors"
	auth "github.com/moapis/authenticator"
	"github.com/moapis/authenticator/models"
	"github.com/moapis/multidb"
	"github.com/pascaldekloe/jwt"
	"github.com/sirupsen/logrus"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"golang.org/x/crypto/argon2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func Test_authServer_newTx(t *testing.T) {
	ex, cancel := context.WithTimeout(context.Background(), -1)
	defer cancel()
	type fields struct {
		mdb *multidb.MultiDB
		log *logrus.Entry
	}
	type args struct {
		ctx      context.Context
		method   string
		readOnly bool
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
				ctx:      context.Background(),
				method:   "some",
				readOnly: true,
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
				ctx:      context.Background(),
				method:   "some",
				readOnly: false,
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
				ctx:      ex,
				method:   "some",
				readOnly: true,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tas.newTx(tt.args.ctx, tt.args.method, tt.args.readOnly)
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

func Test_requestTx_done_commit(t *testing.T) {
	tx, err := tas.newTx(testCtx, "testing", false)
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
	tx, err = tas.newTx(testCtx, "testing", false)
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
		want    *auth.AuthReply
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
			&auth.AuthReply{
				Jwt: "eyJhbGciOiJFZERTQSIsImtpZCI6IjEwIn0.eyJhdWQiOlsiZm9vIiwiYmFyIl0sImV4cCI6ODY1MjMuMDAwMDAwNDU2LCJpYXQiOjEyMy4wMDAwMDA0NTYsImlzcyI6ImxvY2FsaG9zdCIsInNvbWUiOjEsInN1YiI6InRlc3R1c2VyIn0.Ox2PHwJ5Q7u4P2n5y1PZ630hm0J0N4yam14GA4-NSgn-Ak3L9Au2a8GHzN-AoQGbREJA1GDdIwGWIoGS3TthBQ",
			},
			false,
		},
		{
			"Commit error",
			args{
				subject:   "testuser",
				issued:    time.Unix(123, 456),
				set:       map[string]interface{}{"some": 1},
				audiences: []string{"foo", "bar"},
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := tas.newTx(testCtx, "testing", false)
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()

			if tt.name == "Commit error" {
				rt.done()
			}

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
		user   *models.User
		issued time.Time
	}
	tests := []struct {
		name    string
		args    args
		want    *auth.AuthReply
		wantErr bool
	}{
		{
			"No group",
			args{
				testUsers["noGroup"],
				time.Unix(123, 456),
			},
			&auth.AuthReply{
				Jwt: "eyJhbGciOiJFZERTQSIsImtpZCI6IjEwIn0.eyJleHAiOjg2NTIzLjAwMDAwMDQ1NiwiZ3JvdXBzIjpbXSwiaWF0IjoxMjMuMDAwMDAwNDU2LCJpc3MiOiJsb2NhbGhvc3QiLCJzdWIiOiJub0Bncm91cC5jb20iLCJ1c2VyX2lkIjoxMDF9.kon9MoxRtYYbQCTHBvbSlN1YNJtaQJHNr6LIf8HxaIuBYbZLxTdWDqFOO4DLI-opKeSGIn8RxuYH4CtjA3liAQ",
			},
			false,
		},
		{
			"One group",
			args{
				testUsers["oneGroup"],
				time.Unix(123, 456),
			},
			&auth.AuthReply{
				Jwt: "eyJhbGciOiJFZERTQSIsImtpZCI6IjEwIn0.eyJleHAiOjg2NTIzLjAwMDAwMDQ1NiwiZ3JvdXBzIjpbInB1YmxpYyJdLCJpYXQiOjEyMy4wMDAwMDA0NTYsImlzcyI6ImxvY2FsaG9zdCIsInN1YiI6Im9uZUBncm91cC5jb20iLCJ1c2VyX2lkIjoxMDJ9.N0xGJpjch6ca0YmevnbDx-su1B-1TiWXAGxWs3YGHMrOm97XBTCANIfXmqEPqcnYHxksz7RZDhOSHZr5xFzKAw",
			},
			false,
		},
		{
			"All groups",
			args{
				testUsers["allGroups"],
				time.Unix(123, 456),
			},
			&auth.AuthReply{
				Jwt: "eyJhbGciOiJFZERTQSIsImtpZCI6IjEwIn0.eyJleHAiOjg2NTIzLjAwMDAwMDQ1NiwiZ3JvdXBzIjpbInB1YmxpYyIsInVzZXIiLCJhZG1pbiJdLCJpYXQiOjEyMy4wMDAwMDA0NTYsImlzcyI6ImxvY2FsaG9zdCIsInN1YiI6ImFsbEBncm91cHMuY29tIiwidXNlcl9pZCI6MTAzfQ.4_yt_9EavRLkKZLenr-NyPrtncYn3V_YjqJvng46XBIf608l2q9M10cUWL3BL-w4ZB6yxS28ljbEOSB5xwl8CA",
			},
			false,
		},
		{
			"All audiences",
			args{
				testUsers["allAudiences"],
				time.Unix(123, 456),
			},
			&auth.AuthReply{
				Jwt: "eyJhbGciOiJFZERTQSIsImtpZCI6IjEwIn0.eyJhdWQiOlsiYXVkMSIsImF1ZDIiXSwiZXhwIjo4NjUyMy4wMDAwMDA0NTYsImdyb3VwcyI6W10sImlhdCI6MTIzLjAwMDAwMDQ1NiwiaXNzIjoibG9jYWxob3N0Iiwic3ViIjoiYWxsQGF1ZGllbmNlcy5jb20iLCJ1c2VyX2lkIjoxMDR9.FIcQnam1XBnDh-Ux0nsLE5Ecr3FDV3mzEOhssThYEEsiL_YxT3ZcCoxmdzyz0HgwFCdNdho7v9Ell0yk64XGDg",
			},
			false,
		},
		{
			"Error",
			args{
				testUsers["allGroups"],
				time.Unix(123, 456),
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := tas.newTx(testCtx, "testing", false)
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()
			if tt.wantErr {
				rt.done()
			}
			got, err := rt.userAuthReply(tt.args.user, tt.args.issued)
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
			rt, err := tas.newTx(testCtx, "testing", false)
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
					Issuer:    "localhost",
					Subject:   testUsers["allGroups"].Name,
					Expires:   jwt.NewNumericTime(time.Unix(123, 456).Add(24 * time.Hour)),
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
			rt, err := tas.newTx(testCtx, "testing", false)
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
			rt, err := tas.newTx(testCtx, "testing", false)
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
		email string
		name  string
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
			},
			true,
		},
		{
			"Success",
			args{
				"foo@bar.com",
				"foo",
			},
			false,
		},
		{
			"Duplicate",
			args{
				"foo@bar.com",
				"foo",
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := tas.newTx(testCtx, "testing", false)
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()
			want, err := rt.insertPwUser(tt.args.email, tt.args.name)
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

func Test_requestTx_dbAuthError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{
			"Nil error",
			nil,
			nil,
		},
		{
			"No rows",
			sql.ErrNoRows,
			status.Error(codes.Unauthenticated, errCredentials),
		},
		{
			"Other error",
			errors.New("some"),
			status.Error(codes.Internal, errDB),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := tas.newTx(testCtx, "testing", false)
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()
			if err := rt.dbAuthError("action", "entry", tt.err); fmt.Sprint(err) != fmt.Sprint(tt.want) {
				t.Errorf("requestTx.dbAuthError() error = %v, wantErr %v", err, tt.want)
			}
		})
	}
}

func Test_requestTx_findUserByEmail(t *testing.T) {
	type args struct {
		email string
	}
	tests := []struct {
		name    string
		args    args
		want    *models.User
		wantErr bool
	}{
		{
			"Find by email",
			args{
				email: "one@group.com",
			},
			testUsers["oneGroup"],
			false,
		},
		{
			"Missing name and email",
			args{},
			nil,
			true,
		},
		{
			"Not found",
			args{
				email: "spanac",
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := tas.newTx(testCtx, "testing", false)
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()
			got, err := rt.findUserByEmail(tt.args.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestTx.findUserByEmail() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil {
				if got == nil {
					t.Fatalf("requestTx.findUserByEmail() = %+v, want %+v", got, tt.want)
				}
				if tt.want.Email != got.Email {
					t.Fatalf("requestTx.findUserByEmail() = %+v, want %+v", got, tt.want)
				}
			}
		})
	}
}

func Test_requestTx_authenticatePwUser(t *testing.T) {
	m, err := mdb.Master(testCtx)
	if err != nil {
		t.Fatal(err)
	}
	u := &models.User{Email: "no@pwd.com", Name: "noPwd"}
	if err = u.Insert(testCtx, m, boil.Infer()); err != nil {
		t.Fatal(err)
	}

	type args struct {
		email    string
		password string
	}
	tests := []struct {
		name    string
		args    args
		want    *models.User
		wantErr bool
	}{
		{
			"Valid password",
			args{
				email:    "one@group.com",
				password: "oneGroup",
			},
			testUsers["oneGroup"],
			false,
		},
		{
			"Missing password",
			args{
				email: "one@group.com",
			},
			nil,
			true,
		},
		{
			"Missing name and email",
			args{
				password: "oneGroup",
			},
			nil,
			true,
		},
		{
			"Password not found",
			args{
				email:    "no@pwd.com",
				password: "something",
			},
			nil,
			true,
		},
		{
			"Timeout",
			args{
				email:    "one@group.com",
				password: "oneGroup",
			},
			nil,
			true,
		},
		{
			"Wrong password",
			args{
				email:    "one@group.com",
				password: "foobar",
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := tas.newTx(testCtx, "testing", false)
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()

			if tt.name == "Timeout" {
				rt.ctx, rt.cancel = context.WithTimeout(rt.ctx, 500*time.Millisecond)
			}
			defer rt.cancel()

			got, err := rt.authenticatePwUser(tt.args.email, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestTx.authenticatePwUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil {
				if got == nil {
					t.Fatalf("requestTx.authenticatePwUser() = %+v, want %+v", got, tt.want)
				}
				if tt.want.Name != got.Name {
					t.Fatalf("requestTx.authenticatePwUser() = %+v, want %+v", got, tt.want)
				}
			}
		})
	}
}

func Test_requestTx_checkUserExists(t *testing.T) {
	type args struct {
		email string
	}
	tests := []struct {
		name    string
		args    args
		want    *auth.Exists
		wantErr bool
	}{
		{
			"Email exists",
			args{
				email: "one@group.com",
			},
			&auth.Exists{
				Email: true,
			},
			false,
		},
		{
			"E-mail does not exist",
			args{
				email: "no@body.com",
			},
			&auth.Exists{
				Email: false,
			},
			false,
		},
		{
			"Missing email",
			args{
				email: "",
			},
			nil,
			true,
		},
		{
			"DBErr",
			args{
				email: "one@group.com",
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := tas.newTx(testCtx, "testing", false)
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()

			if tt.name == "DBErr" {
				rt.done()
			}

			got, err := rt.checkUserExists(tt.args.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestTx.checkUserExists() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				if got.Email != tt.want.Email {
					t.Errorf("requestTx.checkUserExists() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func Test_requestTx_publicUserToken(t *testing.T) {
	type args struct {
		uuid   string
		issued time.Time
	}
	tests := []struct {
		name    string
		args    args
		want    *auth.AuthReply
		wantErr bool
	}{
		{
			"Ok",
			args{
				uuid:   "super-unique-uuid",
				issued: time.Unix(123, 456),
			},
			&auth.AuthReply{
				Jwt: "eyJhbGciOiJFZERTQSIsImtpZCI6IjEwIn0.eyJpc3MiOiJsb2NhbGhvc3QiLCJzdWIiOiJwdWJsaWM6c3VwZXItdW5pcXVlLXV1aWQiLCJleHAiOjg2NTIzLjAwMDAwMDQ1NiwiaWF0IjoxMjMuMDAwMDAwNDU2fQ.NzH0jqp71uXgbmILuhUK3sn2HYPESDlUlRzQJGrbZr85k7Gh8ZE0ckg8RUzFATvsKCjKOnZojuQ2txcYnFNfCQ",
			},
			false,
		},
		{
			"Empy UUID",
			args{
				uuid:   "",
				issued: time.Unix(123, 456),
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := tas.newTx(testCtx, "testing", false)
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()
			got, err := rt.publicUserToken(tt.args.uuid, tt.args.issued)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestTx.publicUserToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("requestTx.publicUserToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_requestTx_getPubKey(t *testing.T) {
	tests := []struct {
		name    string
		kid     int
		want    *auth.PublicKey
		wantErr bool
	}{
		{
			"Existing key",
			10,
			&auth.PublicKey{Key: []byte(testPubKey)},
			false,
		},
		{
			"Non-existing key",
			666,
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := tas.newTx(testCtx, "testing", false)
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()

			got, err := rt.getPubKey(tt.kid)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestTx.getPubKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("requestTx.getPubKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_requestTx_sendMail(t *testing.T) {
	type args struct {
		template string
		data     mailData
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"Succes",
			args{"test",
				mailData{
					&models.User{
						Name:  "Mickey Mouse",
						Email: "admin@test.mailu.io",
					},
					"moapis/authenticator/cmd/server sendMail unit test",
					"https://github.com/moapis/authenticator",
				},
			},
			false,
		},
		{
			"Template error",
			args{"foobar",
				mailData{
					&models.User{
						Name:  "Mickey Mouse",
						Email: "admin@test.mailu.io",
					},
					"moapis/authenticator/cmd/server sendMail unit test",
					"https://github.com/moapis/authenticator",
				},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := tas.newTx(testCtx, "testing", false)
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()

			if err := rt.sendMail(tt.args.template, tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("requestTx.sendMail() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
