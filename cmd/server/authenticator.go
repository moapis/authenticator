// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"sync"
	"time"

	auth "github.com/moapis/authenticator"
	"github.com/moapis/authenticator/models"
	"github.com/moapis/mailer"
	"github.com/moapis/multidb"
	"github.com/sirupsen/logrus"
	"github.com/volatiletech/sqlboiler/boil"
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
	errMissingEmailOrName = "Missing email or name"
	errMissingPW          = "Missing password"
	errMissingToken       = "JWT token missing"
	errExpiredToken       = "JWT expired"
	errMissingUUID        = "UUID missing"
	errMissingKeyID       = "Public key ID missing"
	errKeyNotFound        = "Key ID not found"
	errFatal              = "Fatal I/O error"
	errDB                 = "Database error"
	errMailer             = "Failed to send verification mail"
)

func callBackURL(cb *auth.CallBackUrl, token string) string {
	buf := bytes.NewBufferString(cb.GetBaseUrl())
	if buf.Len() > 0 {
		buf.WriteByte('?')
	}

	tokenKey := cb.GetTokenKey()
	if tokenKey == "" {
		tokenKey = "token"
	}
	values := url.Values{tokenKey: {token}}
	for k, ss := range cb.GetParams() {
		values[k] = ss.GetSlice()
	}
	buf.WriteString(values.Encode())

	return buf.String()
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

	user, err := rt.authenticatePwUser(up.GetEmail(), up.GetName(), up.GetPassword())
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
		if user, err = rt.authenticatePwUser(up.GetEmail(), up.GetName(), old); err != nil {
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

		user, err = rt.findUserByEmailOrName("", claims.Subject)
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
	return rt.checkUserExists(ud.GetEmail(), ud.GetName())
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
	user, err := rt.findUserByEmailOrName("", claims.Subject)
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
