// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/ed25519"
	"html/template"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	auth "github.com/moapis/authenticator"
	"github.com/moapis/authenticator/models"
	"github.com/moapis/multidb"
	"github.com/pascaldekloe/jwt"
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
				log: tas.log,
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
		rd  *auth.RegistrationData
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
				&auth.RegistrationData{},
			},
			true,
		},
		{
			"Valid user",
			args{
				testCtx,
				&auth.RegistrationData{
					Email: "admin@test.mailu.io",
					Name:  "Mickey Mouse",
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tas.RegisterPwUser(tt.args.ctx, tt.args.rd)
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
		up  *auth.UserPassword
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
				&auth.UserPassword{},
			},
			true,
		},
		{
			"Valid user and passwd",
			args{
				testCtx,
				&auth.UserPassword{
					Email:    "one@group.com",
					Password: "oneGroup",
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tas.AuthenticatePwUser(tt.args.ctx, tt.args.up)
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

	claims := &jwt.Claims{
		KeyID: "10",
		Registered: jwt.Registered{
			Issuer:    "localhost",
			Subject:   testUsers["oneGroup"].Email,
			Audiences: []string{"passwords@localhost"},
			Expires:   jwt.NewNumericTime(time.Now().Add(24 * time.Hour)),
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
			Issuer:    "localhost",
			Subject:   "Nobody",
			Audiences: []string{"passwords@localhost"},
			Expires:   jwt.NewNumericTime(time.Now().Add(24 * time.Hour)),
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

	claims = &jwt.Claims{
		KeyID: "10",
		Registered: jwt.Registered{
			Issuer:    "localhost",
			Subject:   testUsers["oneGroup"].Name,
			Audiences: []string{"spanac"},
			Expires:   jwt.NewNumericTime(time.Now().Add(24 * time.Hour)),
			Issued:    jwt.NewNumericTime(time.Now()),
		},
		Set: map[string]interface{}{
			"user_id":   103,
			"group_ids": []int{1, 2, 3},
		},
	}
	jwtWrongAud, err := claims.EdDSASign([]byte(testPrivKey))
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		ctx context.Context
		up  *auth.NewUserPassword
	}
	tests := []struct {
		name    string
		args    args
		want    *auth.ChangePwReply
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
				&auth.NewUserPassword{},
			},
			nil,
			true,
		},
		{
			"Valid user and passwd",
			args{
				testCtx,
				&auth.NewUserPassword{
					Email:       "one@group.com",
					Credential:  &auth.NewUserPassword_OldPassword{OldPassword: "oneGroup"},
					NewPassword: "oneGroup",
				},
			},
			&auth.ChangePwReply{Success: true},
			false,
		},
		{
			"Wrong passwd",
			args{
				testCtx,
				&auth.NewUserPassword{
					Email:       "one@group.com",
					Credential:  &auth.NewUserPassword_OldPassword{OldPassword: "wrong"},
					NewPassword: "oneGroup",
				},
			},
			nil,
			true,
		},
		{
			"Empty new passwd",
			args{
				testCtx,
				&auth.NewUserPassword{
					Email:       "one@group.com",
					Credential:  &auth.NewUserPassword_OldPassword{OldPassword: "oneGroup"},
					NewPassword: "",
				},
			},
			nil,
			true,
		},
		{
			"Valid user and token",
			args{
				testCtx,
				&auth.NewUserPassword{
					Email:       "one@group.com",
					Credential:  &auth.NewUserPassword_ResetToken{ResetToken: string(jwtKnown)},
					NewPassword: "oneGroup",
				},
			},
			&auth.ChangePwReply{Success: true},
			false,
		},
		{
			"Valid token and unknown user",
			args{
				testCtx,
				&auth.NewUserPassword{
					Email:       "one@group.com",
					Credential:  &auth.NewUserPassword_ResetToken{ResetToken: string(jwtUnKnown)},
					NewPassword: "oneGroup",
				},
			},
			nil,
			true,
		},
		{
			"Valid token and wrong audience",
			args{
				testCtx,
				&auth.NewUserPassword{
					Email:       "one@group.com",
					Credential:  &auth.NewUserPassword_ResetToken{ResetToken: string(jwtWrongAud)},
					NewPassword: "oneGroup",
				},
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tas.ChangeUserPw(tt.args.ctx, tt.args.up)
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
		ud  *auth.UserData
	}
	tests := []struct {
		name    string
		args    args
		want    *auth.Exists
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
				&auth.UserData{},
			},
			nil,
			true,
		},
		{
			"Existing email",
			args{
				testCtx,
				&auth.UserData{Email: "one@group.com"},
			},
			&auth.Exists{Email: true},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tas.CheckUserExists(tt.args.ctx, tt.args.ud)
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
			Issuer:    "localhost",
			Subject:   testUsers["allGroups"].Email,
			Expires:   jwt.NewNumericTime(time.Now().Add(24 * time.Hour)),
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
			Issuer:    "localhost",
			Subject:   "Nobody",
			Expires:   jwt.NewNumericTime(time.Now().Add(24 * time.Hour)),
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
		old *auth.AuthReply
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
				&auth.AuthReply{},
			},
			true,
		},
		{
			"Known User",
			args{
				testCtx,
				&auth.AuthReply{Jwt: string(jwtKnown)},
			},
			false,
		},
		{
			"Unknown User",
			args{
				testCtx,
				&auth.AuthReply{Jwt: string(jwtUnKnown)},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tas.RefreshToken(tt.args.ctx, tt.args.old)
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
		pu  *auth.PublicUser
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
				&auth.PublicUser{},
			},
			true,
		},
		{
			"Valid uuid",
			args{
				testCtx,
				&auth.PublicUser{Uuid: "somethingRndm"},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tas.PublicUserToken(tt.args.ctx, tt.args.pu)
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
		k   *auth.KeyID
	}
	tests := []struct {
		name    string
		args    args
		want    *auth.PublicKey
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
				&auth.KeyID{},
			},
			nil,
			true,
		},
		{
			"Known Kid",
			args{
				testCtx,
				&auth.KeyID{Kid: 10},
			},
			&auth.PublicKey{Key: []byte(testPubKey)},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tas.GetPubKey(tt.args.ctx, tt.args.k)
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

func Test_callBackURL(t *testing.T) {
	type args struct {
		cb    *auth.CallBackUrl
		token string
	}
	tests := []struct {
		name string
		args args
		want template.URL
	}{
		{
			"Only token",
			args{
				nil,
				"foobar",
			},
			"token=foobar",
		},
		{
			"Set token key and Base URL",
			args{
				&auth.CallBackUrl{
					BaseUrl:  "http://example.com",
					TokenKey: "key",
				},
				"foobar",
			},
			"http://example.com?key=foobar",
		},
		{
			"Additional params",
			args{
				&auth.CallBackUrl{
					BaseUrl:  "http://example.com",
					TokenKey: "key",
					Params: map[string]*auth.StringSlice{
						"hello": {Slice: []string{"world", "mars"}},
					},
				},
				"foobar",
			},
			"http://example.com?key=foobar&hello=world&hello=mars",
		},
		{
			"With redirect",
			args{
				&auth.CallBackUrl{
					BaseUrl:  "http://example.com",
					TokenKey: "key",
					Params: map[string]*auth.StringSlice{
						"redirect": {Slice: []string{"http://redirect.to/here"}},
					},
				},
				"foobar",
			},
			"http://example.com?key=foobar&redirect=http://redirect.to/here",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := callBackURL(tt.args.cb, tt.args.token); got != tt.want {
				t.Errorf("callBackURL() =\n%v\nwant\n%v", got, tt.want)
			}
		})
	}
}

func Test_authServer_ResetUserPW(t *testing.T) {
	ectx, cancel := context.WithCancel(testCtx)
	cancel()

	type args struct {
		ctx context.Context
		ue  *auth.UserEmail
	}
	tests := []struct {
		name    string
		args    args
		want    *empty.Empty
		wantErr bool
	}{
		{
			"Context error",
			args{
				ectx,
				nil,
			},
			nil,
			true,
		},
		{
			"Mssing e-mail",
			args{
				testCtx,
				&auth.UserEmail{
					Email: "",
				},
			},
			nil,
			true,
		},
		{
			"Non-existent e-mail",
			args{
				testCtx,
				&auth.UserEmail{
					Email: "does-not@exist.com",
					Url: &auth.CallBackUrl{
						BaseUrl:  "http://localhost:1234/setpw",
						TokenKey: "jwt",
					},
				},
			},
			nil,
			true,
		},
		{
			"Success",
			args{
				testCtx,
				&auth.UserEmail{
					Email: "all@audiences.com",
					Url: &auth.CallBackUrl{
						BaseUrl:  "http://localhost:1234/setpw",
						TokenKey: "jwt",
					},
				},
			},
			&empty.Empty{},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tas.ResetUserPW(tt.args.ctx, tt.args.ue)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.ResetUserPW() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authServer.ResetUserPW() = %v, want %v", got, tt.want)
			}
		})
	}
}
