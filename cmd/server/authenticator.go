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

	"github.com/moapis/authenticator/models"
	pb "github.com/moapis/authenticator/pb"
	"github.com/moapis/mailer"
	"github.com/moapis/multidb"
	"github.com/sirupsen/logrus"
	"github.com/volatiletech/sqlboiler/boil"
)

type privateKey struct {
	id  string
	key ed25519.PrivateKey
}

type authServer struct {
	pb.UnimplementedAuthenticatorServer

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

func callBackURL(cb *pb.CallBackUrl, token string) string {
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

func (s *authServer) RegisterPwUser(ctx context.Context, rd *pb.RegistrationData) (*pb.RegistrationReply, error) {
	rt, err := s.newTx(ctx, "RegisterPwUser", false)
	if err != nil {
		return nil, err
	}
	defer rt.done()

	user, err := rt.insertPwUser(rd.GetEmail(), rd.GetName())
	if err != nil {
		return nil, err
	}
	auth, err := rt.authReply(user.Email, time.Now(), nil, fmt.Sprintf("verify@%s", rt.s.conf.JWT.Issuer))
	if err != nil {
		return nil, err
	}
	if err := rt.sendMail(
		"registration", mailData{
			user, registrationSubject,
			callBackURL(
				rd.GetUrl(),
				auth.GetJwt(),
			),
		},
	); err != nil {
		return nil, err
	}

	return &pb.RegistrationReply{UserId: int32(user.ID)}, nil
}

func (s *authServer) AuthenticatePwUser(ctx context.Context, up *pb.UserPassword) (*pb.AuthReply, error) {
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

func (s *authServer) ChangeUserPw(ctx context.Context, up *pb.NewUserPassword) (*pb.ChangePwReply, error) {
	rt, err := s.newTx(ctx, "ChangeUserPw", false)
	if err != nil {
		return nil, err
	}
	defer rt.done()

	user, err := rt.authenticatePwUser(up.GetEmail(), up.GetName(), up.GetOldPassword())
	if err != nil {
		return nil, err
	}
	if err = rt.setUserPassword(user, up.GetNewPassword(), rand.Read); err != nil {
		return nil, err
	}
	if err = rt.commit(); err != nil {
		return nil, err
	}
	return &pb.ChangePwReply{Success: true}, nil
}

func (s *authServer) CheckUserExists(ctx context.Context, ud *pb.UserData) (*pb.Exists, error) {
	rt, err := s.newTx(ctx, "CheckUserExistsUserPw", true)
	if err != nil {
		return nil, err
	}
	defer rt.done()
	return rt.checkUserExists(ud.GetEmail(), ud.GetName())
}

func (s *authServer) RefreshToken(ctx context.Context, old *pb.AuthReply) (*pb.AuthReply, error) {
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

func (s *authServer) PublicUserToken(ctx context.Context, pu *pb.PublicUser) (*pb.AuthReply, error) {
	rt, err := s.newTx(ctx, "PublicUserToken", true)
	if err != nil {
		return nil, err
	}
	defer rt.done()
	return rt.publicUserToken(pu.GetUuid(), time.Now())
}

func (s *authServer) GetPubKey(ctx context.Context, k *pb.KeyID) (*pb.PublicKey, error) {
	rt, err := s.newTx(ctx, "GetPubKey", true)
	if err != nil {
		return nil, err
	}
	defer rt.done()
	return rt.getPubKey(int(k.GetKid()))
}
