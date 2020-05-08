// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"time"

	"github.com/friendsofgo/errors"
	"golang.org/x/crypto/argon2"

	auth "github.com/moapis/authenticator"
	"github.com/moapis/authenticator/models"
	"github.com/moapis/authenticator/verify"
	"github.com/moapis/mailer"
	"github.com/pascaldekloe/jwt"
	"github.com/sirupsen/logrus"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"github.com/volatiletech/sqlboiler/v4/queries/qm"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// requestTx holds the request transaction, context and reference to authServer
type requestTx struct {
	tx       boil.ContextTransactor
	ctx      context.Context
	cancel   context.CancelFunc
	log      *logrus.Entry
	s        *authServer
	readOnly bool
}

func (s *authServer) newTx(ctx context.Context, method string, readOnly bool) (*requestTx, error) {
	rt := &requestTx{
		log:      s.log.WithField("method", method),
		s:        s,
		readOnly: readOnly,
	}
	var err error
	if readOnly {
		rt.tx, err = s.mdb.MultiTx(ctx, &sql.TxOptions{ReadOnly: readOnly}, s.conf.SQLRoutines)
	} else {
		rt.tx, err = s.mdb.MasterTx(ctx, nil)
	}
	if err != nil {
		rt.log.WithError(err).Error("Begin TX")
		return nil, err
	}
	rt.log.Debug("Begin TX")
	rt.ctx, rt.cancel = context.WithCancel(ctx)
	return rt, nil
}

const errNotEnoughTime = "Not enough time in context"

// EnoughTime checks if the context is valid and has enough time available.
func (rt *requestTx) enoughTime(need time.Duration) error {
	if err := rt.ctx.Err(); err != nil {
		rt.log.WithError(err).Warn("enoughTime")
		return status.FromContextError(err).Err()
	}
	dl, ok := rt.ctx.Deadline()
	ll := rt.log.WithFields(logrus.Fields{"deadline": dl, "need": need})
	if need != 0 && ok && time.Now().Add(need).After(dl) {
		ll.WithError(errors.New(errNotEnoughTime)).Warn("enoughTime")
		return status.Error(codes.Aborted, errNotEnoughTime)
	}
	ll.Debug("enoughTime")
	return nil
}

// done is meant to be deferred and errors are logged, not returned
func (rt *requestTx) done() {
	err := rt.tx.Rollback()
	rt.cancel()

	if err != nil {
		rt.log.WithError(err).Error("TX Rollback")
	} else {
		rt.log.Debug("TX Rollback")
	}
}

func (rt *requestTx) commit() error {
	err := rt.tx.Commit()
	if err != nil {
		rt.log.WithError(err).Error("TX commit")
		return status.Error(codes.Internal, errDB)
	}
	rt.log.Debug("TX Commit")
	return nil
}

const (
	errToken       = "JWT error"
	errCredentials = "Invalid credentials"

	jwtUserID = "user_id"
	jwtGroups = "groups"
)

func (rt *requestTx) authReply(subject string, issued time.Time, set map[string]interface{}, audiences ...string) (*auth.AuthReply, error) {
	prKey := rt.s.privateKey()
	c := jwt.Claims{
		KeyID: prKey.id,
		Registered: jwt.Registered{
			Issuer:    rt.s.conf.JWT.Issuer,
			Subject:   subject,
			Expires:   jwt.NewNumericTime(issued.Add(rt.s.conf.JWT.Expiry)),
			Audiences: audiences,
			Issued:    jwt.NewNumericTime(issued),
		},
		Set: set,
	}
	rt.log = rt.log.WithField("claims", c)

	token, err := c.EdDSASign(prKey.key)
	if err != nil {
		rt.log.WithError(err).Error("authReply")
		return nil, status.Error(codes.Internal, errToken)
	}
	st := string(token)
	rt.log.WithField("token", st).Debug("authReply")

	if !rt.readOnly {
		if err = rt.commit(); err != nil {
			rt.log.WithError(err).Error("commit()")
			return nil, status.Error(codes.Internal, errDB)
		}
	}
	return &auth.AuthReply{Jwt: st}, nil
}

func (rt *requestTx) userAuthReply(user *models.User, issued time.Time) (*auth.AuthReply, error) {
	rt.log = rt.log.WithField("user", user)
	audiences, err := user.Audiences(qm.Select(models.AudienceColumns.Name)).All(rt.ctx, rt.tx)
	if err != nil {
		rt.log.WithError(err).Error("userAuthReply")
		return nil, status.Error(codes.Internal, errDB)
	}
	rt.log.WithField("audiences", audiences).Debug("userAuthReply")

	groups, err := user.Groups(qm.Select(models.GroupColumns.Name)).All(rt.ctx, rt.tx)
	if err != nil {
		rt.log.WithError(err).Error("userAuthReply")
		return nil, status.Error(codes.Internal, errDB)
	}
	rt.log.WithField("groups", groups).Debug("userAuthReply")

	gns := make([]string, len(groups))
	for i, g := range groups {
		gns[i] = g.Name
	}

	ans := make([]string, len(audiences))
	for i, a := range audiences {
		ans[i] = a.Name
	}

	return rt.authReply(
		user.Email,
		issued,
		map[string]interface{}{
			jwtUserID: user.ID,
			jwtGroups: gns,
		},
		ans...,
	)
}

func (rt *requestTx) findJWTKey(kid int) ([]byte, error) {
	rt.log = rt.log.WithField("KeyID", kid)
	if kid == 0 {
		rt.log.WithError(errors.New(errMissingKeyID)).Warn("getPubKey")
		return nil, status.Error(codes.InvalidArgument, errMissingKeyID)
	}
	key, err := models.FindJWTKey(rt.ctx, rt.tx, kid, models.JWTKeyColumns.PublicKey)
	switch err {
	case nil:
		break
	case sql.ErrNoRows:
		rt.log.WithError(err).Warn("getPubKey")
		return nil, status.Error(codes.NotFound, errKeyNotFound)
	default:
		rt.log.WithError(err).Error("getPubKey")
		return nil, status.Error(codes.Internal, errDB)
	}
	return key.PublicKey, nil
}

func (rt *requestTx) checkJWT(token string, valid time.Time) (*jwt.Claims, error) {
	log := rt.log.WithField("token", token)
	if token == "" {
		log.WithError(errors.New(errMissingToken)).Warn("checkJWT")
		return nil, status.Error(codes.InvalidArgument, errMissingToken)
	}
	kid, err := verify.ParseJWTHeader(token)
	if err != nil {
		log.WithError(err).Warn("tokens.ParseJWTHeader()")
		return nil, status.Error(codes.Unauthenticated, "Invalid token header")
	}
	key, err := rt.findJWTKey(kid)
	if err != nil {
		return nil, err
	}
	claims, err := jwt.EdDSACheck([]byte(token), []byte(key))
	if err != nil {
		log.WithError(err).Warn("jwt.EdDSACheck()")
		return nil, status.Error(codes.Unauthenticated, "EdDSA verification failed")
	}
	if !claims.Valid(valid) {
		log.WithError(errors.New(errExpiredToken)).Warn("jwt.EdDSACheck()")
		return nil, status.Error(codes.Unauthenticated, errExpiredToken)
	}
	return claims, nil
}

const (
	// PasswordSaltLen is the amount of bytes used for salting passwords
	PasswordSaltLen = 8
	// Argon2Time sets the time argument to the argon2 password hasher
	Argon2Time = 1
	// Argon2Memory sets the memory argument to the argon2 password hasher
	Argon2Memory = 64 * 1024
	// Argon2Threads sets the threads argument to the argon2 password hasher
	Argon2Threads = 2
	// Argon2KeyLen sets the keyLen argument to the argon2 password hasher
	Argon2KeyLen = 32
)

func (rt *requestTx) setUserPassword(user *models.User, password string, read func([]byte) (int, error)) error {
	log := rt.log.WithField("method", "setUserPassword()")
	if password == "" {
		log.Warn(errMissingPW)
		return status.Error(codes.InvalidArgument, errMissingPW)
	}
	pwm := &models.Password{
		UserID: user.ID,
		Salt:   make([]byte, PasswordSaltLen),
	}
	if _, err := read(pwm.Salt); err != nil {
		log.WithError(err).Error("Salt generation")
		return status.Error(codes.Internal, errFatal)
	}
	pwm.Hash = argon2.IDKey([]byte(password), pwm.Salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	log = log.WithField("password_model", pwm)

	if err := pwm.Upsert(
		rt.ctx, rt.tx, true,
		[]string{models.PasswordColumns.UserID},
		boil.Blacklist(
			models.PasswordColumns.UserID,
			models.PasswordColumns.CreatedAt,
		),
		boil.Infer(),
	); err != nil {
		log.WithError(err).Error("password.Upsert()")
		return status.Error(codes.Internal, errDB)
	}
	log.Debug("password.Upsert()")
	return nil
}

func (rt *requestTx) insertPwUser(email, name string) (*models.User, error) {
	rt.log = rt.log.WithFields(logrus.Fields{"email": email, "name": name})
	if email == "" {
		rt.log.WithError(errors.New(errMissingEmail)).Warn("insertPWUser")
		return nil, status.Error(codes.InvalidArgument, errMissingEmail)
	}
	rt.log.Debug("insertPwUser")

	user := &models.User{
		Email: email,
		Name:  name,
	}
	//TODO: check for duplicate error
	if err := user.Insert(rt.ctx, rt.tx, boil.Infer()); err != nil {
		rt.log.WithError(err).Error("Insert user")
		return nil, status.Error(codes.Internal, errDB)
	}
	rt.log.Debug("Insert user")
	return user, nil
}

func (rt *requestTx) dbAuthError(action, entry string, err error) error {
	log := rt.log.WithError(err).WithFields(logrus.Fields{"action": action})
	switch err {
	case nil:
		return nil
	case sql.ErrNoRows:
		log.Warnf("%s not found", entry)
		return status.Error(codes.Unauthenticated, errCredentials)
	default:
		log.Error(errDB)
		return status.Error(codes.Internal, errDB)
	}
}

func (rt *requestTx) findUserByEmail(email string) (*models.User, error) {
	rt.log = rt.log.WithFields(logrus.Fields{"email": email})

	if email == "" {
		rt.log.Warn(errors.New(errMissingEmail))
		return nil, status.Error(codes.InvalidArgument, errMissingEmail)
	}

	user, err := models.Users(models.UserWhere.Email.EQ(email)).One(rt.ctx, rt.tx)
	if err != nil {
		return nil, rt.dbAuthError("findUserByEmail", "user", err)
	}

	rt.log.WithField("user", user).Debug("findUserByEmail")
	return user, nil
}

func (rt *requestTx) authenticatePwUser(email, password string) (*models.User, error) {
	rt.log = rt.log.WithFields(logrus.Fields{"email": email, "passwordLen": len(password)})
	// email presence are checked by findUserByEmail
	if password == "" {
		rt.log.Warn(errMissingPW)
		return nil, status.Error(codes.InvalidArgument, errMissingPW)
	}

	user, err := rt.findUserByEmail(email)
	if err != nil {
		return nil, err
	}
	pwm, err := user.Password().One(rt.ctx, rt.tx)
	if err != nil {
		return nil, rt.dbAuthError("Get user password", "password", err)
	}
	if err := rt.enoughTime(time.Second); err != nil {
		return nil, err
	}

	if string(pwm.Hash) != string(argon2.IDKey([]byte(password), pwm.Salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)) {
		log.WithError(errors.New(errCredentials)).Warn("Password missmatch")
		return nil, status.Error(codes.Unauthenticated, errCredentials)
	}
	return user, nil
}

func (rt *requestTx) checkUserExists(email string) (*auth.Exists, error) {
	rt.log = rt.log.WithFields(logrus.Fields{"email": email})
	if email == "" {
		rt.log.Warn(errors.New(errMissingEmail))
		return nil, status.Error(codes.InvalidArgument, errMissingEmail)
	}
	rt.log.Debug("checkUserExists")

	exists := new(auth.Exists)

	_, err := models.Users(models.UserWhere.Email.EQ(email)).One(rt.ctx, rt.tx)
	switch err {
	case nil:
		exists.Email = true
	case sql.ErrNoRows:
		rt.log.WithError(err).Debug("checkUserExists")
		exists.Email = false
	default:
		rt.log.WithError(err).Error("checkUserExists")
		return nil, status.Error(codes.Internal, errDB)
	}

	rt.log.WithField("exists:", exists).Debug("checkUserExists")
	return exists, nil
}

func (rt *requestTx) publicUserToken(uuid string, issued time.Time) (*auth.AuthReply, error) {
	rt.log = rt.log.WithField("uuid", uuid)
	if uuid == "" {
		rt.log.WithError(errors.New(errMissingUUID)).Warn("publicUserToken")
		return nil, status.Error(codes.InvalidArgument, errMissingUUID)
	}
	rt.log.Debug("publicUserToken")
	return rt.authReply(fmt.Sprintf("public:%s", uuid), issued, nil)
}

func (rt *requestTx) getPubKey(kid int) (*auth.PublicKey, error) {
	key, err := rt.findJWTKey(kid)
	if err != nil {
		return nil, err
	}
	return &auth.PublicKey{Key: key}, nil
}

type mailData struct {
	*models.User
	Subject string
	URL     template.URL
}

func (rt *requestTx) sendMail(template string, data mailData) error {
	headers := []mailer.Header{
		{Key: "from", Values: []string{rt.s.conf.Mail.From}},
		{Key: "subject", Values: []string{data.Subject}},
		{Key: "to", Values: []string{data.Email}},
	}
	log := rt.log.WithFields(logrus.Fields{"headers": headers, "data": data})

	if err := rt.s.mail.Send(headers, template, data, data.Email); err != nil {
		log.WithError(err).Error("sendMail")
		return status.Error(codes.Internal, "Mailer error")
	}
	log.Debug("sendMail")
	return nil
}
