// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	auth "github.com/moapis/authenticator"
	"github.com/moapis/authenticator/models"
	"github.com/moapis/mailer"
	"github.com/moapis/multidb"
	"github.com/sirupsen/logrus"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type privateKey struct {
	id  string
	key ed25519.PrivateKey
}

type authServer struct {
	auth.UnimplementedAuthenticatorServer

	mdb     *multidb.MultiDB
	privKey privateKey
	keyMtx  sync.RWMutex //Protects privKey during updates
	log     *logrus.Entry
	conf    *ServerConfig
	mail    *mailer.Mailer
}

func (s *authServer) updateKeyPair(ctx context.Context, r io.Reader) error {
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return err
	}
	log := s.log.WithField("pub", string(pub))
	log.Debug("Generated key")
	m := &models.JWTKey{
		PublicKey: pub,
	}
	db, err := s.mdb.Master(ctx)
	if err != nil {
		return err
	}
	if err = m.Insert(ctx, db, boil.Infer()); err != nil {
		log.WithError(err).Error("Insert pub key")
		return err
	}
	log = log.WithField("id", m.ID)
	log.Debug("Insert pub key")

	pk := privateKey{
		id:  strconv.Itoa(m.ID),
		key: priv,
	}

	s.keyMtx.Lock()
	s.privKey = pk
	s.keyMtx.Unlock()

	log.Info("JWT keypair update complete")

	return nil
}

func (s *authServer) privateKey() privateKey {
	s.keyMtx.RLock()
	p := s.privKey
	s.keyMtx.RUnlock()
	return p
}

const (
	errMissingEmail = "Missing email"
	errMissingPW    = "Missing password"
	errMissingToken = "JWT token missing"
	errExpiredToken = "JWT expired"
	errMissingUUID  = "UUID missing"
	errMissingKeyID = "Public key ID missing"
	errKeyNotFound  = "Key ID not found"
	errFatal        = "Fatal I/O error"
	errDB           = "Database error"
	errMailer       = "Failed to send verification mail"
)

func callBackURL(cb *auth.CallBackUrl, token string) template.URL {
	b := new(strings.Builder)

	b.WriteString(cb.GetBaseUrl())
	if b.Len() > 0 {
		b.WriteByte('?')
	}

	tokenKey := cb.GetTokenKey()
	if tokenKey == "" {
		tokenKey = "token"
	}
	fmt.Fprintf(b, "%s=%s", tokenKey, token)

	for k, ss := range cb.GetParams() {
		for _, v := range ss.GetSlice() {
			fmt.Fprintf(b, "&%s=%s", k, v)
		}
	}

	return template.URL(b.String())
}

const (
	registrationSubject = "Please verify your e-mail"
)

func (s *authServer) passwordAudience() string {
	return fmt.Sprintf("passwords@%s", s.conf.JWT.Issuer)
}

func (s *authServer) RegisterPwUser(ctx context.Context, rd *auth.RegistrationData) (*auth.RegistrationReply, error) {
	rt, err := s.newTx(ctx, "RegisterPwUser", false)
	if err != nil {
		return nil, err
	}
	defer rt.done()

	user, err := rt.insertPwUser(rd.GetEmail(), rd.GetName())
	if err != nil {
		return nil, err
	}
	reply, err := rt.authReply(user.Name, time.Now(), nil, s.passwordAudience())
	if err != nil {
		return nil, err
	}
	if err := rt.sendMail(
		"registration", mailData{
			user, registrationSubject,
			callBackURL(
				rd.GetUrl(),
				reply.GetJwt(),
			),
		},
	); err != nil {
		return nil, err
	}

	return &auth.RegistrationReply{UserId: int32(user.ID)}, nil
}

func (s *authServer) AuthenticatePwUser(ctx context.Context, up *auth.UserPassword) (*auth.AuthReply, error) {
	rt, err := s.newTx(ctx, "AuthenticatePwUser", true)
	if err != nil {
		return nil, err
	}
	defer rt.done()

	user, err := rt.authenticatePwUser(up.GetEmail(), up.GetPassword())
	if err != nil {
		return nil, err
	}

	return rt.userAuthReply(user, time.Now())
}

func (s *authServer) hasPasswordAudience(audiences []string) error {
	b := s.passwordAudience()
	for _, a := range audiences {
		if a == b {
			return nil
		}
	}
	return status.Error(codes.Unauthenticated, "Not a passwords audience")
}

func (s *authServer) ChangeUserPw(ctx context.Context, up *auth.NewUserPassword) (*auth.ChangePwReply, error) {
	rt, err := s.newTx(ctx, "ChangeUserPw", false)
	if err != nil {
		return nil, err
	}
	defer rt.done()

	var user *models.User
	if old := up.GetOldPassword(); old != "" {
		if user, err = rt.authenticatePwUser(up.GetEmail(), old); err != nil {
			return nil, err
		}
	} else {
		claims, err := rt.checkJWT(up.GetResetToken(), time.Now())
		if err != nil {
			return nil, err
		}
		if err = s.hasPasswordAudience(claims.Audiences); err != nil {
			return nil, err
		}

		user, err = rt.findUserByEmail(claims.Subject)
		if err != nil {
			return nil, err
		}
	}

	if err = rt.setUserPassword(user, up.GetNewPassword(), rand.Read); err != nil {
		return nil, err
	}
	if err = rt.commit(); err != nil {
		return nil, err
	}
	return &auth.ChangePwReply{Success: true}, nil
}

func (s *authServer) CheckUserExists(ctx context.Context, ud *auth.UserData) (*auth.Exists, error) {
	rt, err := s.newTx(ctx, "CheckUserExistsUserPw", true)
	if err != nil {
		return nil, err
	}
	defer rt.done()
	return rt.checkUserExists(ud.GetEmail())
}

func (s *authServer) RefreshToken(ctx context.Context, old *auth.AuthReply) (*auth.AuthReply, error) {
	rt, err := s.newTx(ctx, "RefreshToken", true)
	if err != nil {
		return nil, err
	}
	defer rt.done()
	claims, err := rt.checkJWT(old.GetJwt(), time.Now())
	if err != nil {
		return nil, err
	}
	user, err := rt.findUserByEmail(claims.Subject)
	if err != nil {
		return nil, err
	}
	return rt.userAuthReply(user, time.Now())
}

func (s *authServer) PublicUserToken(ctx context.Context, pu *auth.PublicUser) (*auth.AuthReply, error) {
	rt, err := s.newTx(ctx, "PublicUserToken", true)
	if err != nil {
		return nil, err
	}
	defer rt.done()
	return rt.publicUserToken(pu.GetUuid(), time.Now())
}

func (s *authServer) GetPubKey(ctx context.Context, k *auth.KeyID) (*auth.PublicKey, error) {
	rt, err := s.newTx(ctx, "GetPubKey", true)
	if err != nil {
		return nil, err
	}
	defer rt.done()
	return rt.getPubKey(int(k.GetKid()))
}

const (
	pwResetSubject = "Password reset link"
)

func (s *authServer) ResetUserPW(ctx context.Context, ue *auth.UserEmail) (*empty.Empty, error) {
	rt, err := s.newTx(ctx, "ResetUserPW", false)
	if err != nil {
		return nil, err
	}
	defer rt.done()

	email := ue.GetEmail()
	if email == "" {
		rt.log.Warn(errMissingEmail)
		return nil, status.Error(codes.InvalidArgument, errMissingEmail)
	}

	user, err := rt.findUserByEmail(ue.GetEmail())
	if err != nil {
		return nil, status.Error(codes.NotFound, "User not found")
	}
	reply, err := rt.authReply(user.Email, time.Now(), nil, s.passwordAudience())
	if err != nil {
		return nil, err
	}
	if err := rt.sendMail(
		"reset", mailData{
			user, pwResetSubject,
			callBackURL(
				ue.GetUrl(),
				reply.GetJwt(),
			),
		},
	); err != nil {
		return nil, err
	}

	return &empty.Empty{}, nil
}
