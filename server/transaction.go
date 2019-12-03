// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"time"

	"github.com/friendsofgo/errors"
	"golang.org/x/crypto/argon2"

	"github.com/moapis/authenticator/models"
	pb "github.com/moapis/authenticator/pb"
	"github.com/moapis/authenticator/tokens"
	"github.com/pascaldekloe/jwt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/volatiletech/sqlboiler/boil"
	"github.com/volatiletech/sqlboiler/queries/qm"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func init() {
	viper.SetDefault("JWTIssuer", "localhost")
	viper.SetDefault("JWTExpiry", 24*time.Hour)
}

// requestTx holds the request transaction, context and reference to authServer
type requestTx struct {
	tx     boil.ContextTransactor
	ctx    context.Context
	cancel context.CancelFunc
	log    *logrus.Entry
	s      *authServer
}

func (s *authServer) newTx(ctx context.Context, method string, master bool) (*requestTx, error) {
	rt := &requestTx{
		log: s.log.WithField("method", method),
		s:   s,
	}
	var err error
	if master {
		rt.tx, err = s.mdb.MasterTx(ctx, nil)
	} else {
		rt.tx, err = s.mdb.MultiTx(ctx, nil, viper.GetInt("DBRoutines"))
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

	jwtUserID   = "user_id"
	jwtGroupIDs = "group_ids"
)

func (rt *requestTx) authReply(subject string, issued time.Time, set map[string]interface{}, audiences ...string) (*pb.AuthReply, error) {
	prKey := rt.s.privateKey()
	c := jwt.Claims{
		KeyID: prKey.id,
		Registered: jwt.Registered{
			Issuer:    viper.GetString("JWTIssuer"),
			Subject:   subject,
			Expires:   jwt.NewNumericTime(issued.Add(viper.GetDuration("JWTExpiry"))),
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
	return &pb.AuthReply{Jwt: st}, nil
}

func (rt *requestTx) userAuthReply(user *models.User, issued time.Time, audiences ...string) (*pb.AuthReply, error) {
	rt.log = rt.log.WithField("user", user)
	groups, err := user.Groups(qm.Select(models.GroupColumns.ID)).All(rt.ctx, rt.tx)
	if err != nil {
		rt.log.WithError(err).Error("userAuthReply")
		return nil, status.Error(codes.Internal, errDB)
	}
	rt.log.WithField("groups", groups).Debug("userAuthReply")

	gIDs := make([]int, 0, len(groups))
	for _, g := range groups {
		gIDs = append(gIDs, g.ID)
	}
	return rt.authReply(
		user.Name,
		issued,
		map[string]interface{}{
			jwtUserID:   user.ID,
			jwtGroupIDs: gIDs,
		},
		audiences...,
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
	kid, err := tokens.ParseJWTHeader(token)
	if err != nil {
		log.WithError(err).Warn("tokens.ParseJWTHeader()")
		return nil, status.Error(codes.Unauthenticated, tokens.ErrKeyVerification)
	}
	key, err := rt.findJWTKey(kid)
	if err != nil {
		return nil, err
	}
	claims, err := jwt.EdDSACheck([]byte(token), []byte(key))
	if err != nil {
		log.WithError(err).Warn("jwt.EdDSACheck()")
		return nil, status.Error(codes.Unauthenticated, tokens.ErrKeyVerification)
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

func (rt *requestTx) insertPwUser(email, name, password string) (*models.User, error) {
	rt.log = rt.log.WithFields(logrus.Fields{"email": email, "name": name, "passwordLen": len(password)})
	if email == "" || name == "" {
		rt.log.WithError(errors.New(errMissingEmailOrName)).Warn("insertPWUser")
		return nil, status.Error(codes.InvalidArgument, errMissingEmailOrName)
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

	return user, rt.setUserPassword(user, password, rand.Read)
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

func (rt *requestTx) findUserByValue(key, value string, columns ...string) (*models.User, error) {
	ll := rt.log.WithFields(logrus.Fields{key: value, "columns": columns})

	qms := []qm.QueryMod{
		qm.Select(columns...),
		qm.Where(fmt.Sprintf("%s=$1", key), value),
	}
	ll.WithField("qms", qms).Debug("findUserByValue")
	return models.Users(qms...).One(rt.ctx, rt.tx)
}

func (rt *requestTx) findUserByEmailOrName(email, name string) (user *models.User, err error) {
	rt.log = rt.log.WithFields(logrus.Fields{"email": email, "name": name})

	switch {
	case email != "":
		user, err = rt.findUserByValue(models.UserColumns.Email, email)
	case name != "":
		user, err = rt.findUserByValue(models.UserColumns.Name, name)
	default:
		rt.log.Warn(errors.New(errMissingEmailOrName))
		return nil, status.Error(codes.InvalidArgument, errMissingEmailOrName)
	}
	if err != nil {
		return nil, rt.dbAuthError("findUserByEmailOrName", "user", err)
	}
	rt.log.WithField("user", user).Debug("findUserByEmailOrName")
	return user, nil
}

func (rt *requestTx) authenticatePwUser(email, name, password string) (*models.User, error) {
	rt.log = rt.log.WithFields(logrus.Fields{"email": email, "name": name, "passwordLen": len(password)})
	// email and name presence are checked by findUserByEmailOrName
	if password == "" {
		rt.log.Warn(errMissingPW)
		return nil, status.Error(codes.InvalidArgument, errMissingPW)
	}

	user, err := rt.findUserByEmailOrName(email, name)
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

func (rt *requestTx) userExistsByValue(key, value string) (bool, error) {
	_, err := rt.findUserByValue(key, value, models.UserColumns.ID)
	switch err {
	case nil:
		return true, nil
	case sql.ErrNoRows:
		rt.log.WithError(err).Debug("userExistsByValue")
		return false, nil
	default:
		rt.log.WithError(err).Error("userExistsByValue")
		return false, status.Error(codes.Internal, errDB)
	}
}

func (rt *requestTx) checkUserExists(email, name string) (*pb.Exists, error) {
	rt.log = rt.log.WithFields(logrus.Fields{"email": email, "name": name})
	if email == "" && name == "" {
		rt.log.Warn(errors.New(errMissingEmailOrName))
		return nil, status.Error(codes.InvalidArgument, errMissingEmailOrName)
	}
	rt.log.Debug("checkUserExists")

	exists := new(pb.Exists)
	var err error

	if email != "" {
		if exists.Email, err = rt.userExistsByValue(models.UserColumns.Email, email); err != nil {
			return nil, err
		}
	}

	if name != "" {
		if exists.Name, err = rt.userExistsByValue(models.UserColumns.Name, name); err != nil {
			return nil, err
		}
	}
	rt.log.WithField("exists:", exists).Debug("checkUserExists")
	return exists, nil
}

func (rt *requestTx) publicUserToken(uuid string, issued time.Time) (*pb.AuthReply, error) {
	rt.log = rt.log.WithField("uuid", uuid)
	if uuid == "" {
		rt.log.WithError(errors.New(errMissingUUID)).Warn("publicUserToken")
		return nil, status.Error(codes.InvalidArgument, errMissingUUID)
	}
	rt.log.Debug("publicUserToken")
	return rt.authReply(fmt.Sprintf("public:%s", uuid), issued, nil)
}

func (rt *requestTx) getPubKey(kid int) (*pb.PublicKey, error) {
	key, err := rt.findJWTKey(kid)
	if err != nil {
		return nil, err
	}
	return &pb.PublicKey{Key: key}, nil
}
