package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/pascaldekloe/jwt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/moapis/authenticator/models"
	pb "github.com/moapis/authenticator/pb"
	"github.com/moapis/authenticator/tokens"
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
	tx     *sql.Tx
	ctx    context.Context
	cancel context.CancelFunc
	log    *logrus.Entry
	s      *authServer
}

func (s *authServer) newTx(ctx context.Context, method string) (*requestTx, error) {
	rt := &requestTx{
		log: s.log.WithField("method", method),
		s:   s,
	}
	var err error
	rt.tx, err = s.db.BeginTx(ctx, nil)
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
		return
	}
	rt.log.Debug("TX Rollback")
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

func (rt *requestTx) userAuthReply(user *models.User, audiences ...string) (*pb.AuthReply, error) {
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
		map[string]interface{}{
			jwtUserID:   user.ID,
			jwtGroupIDs: gIDs,
		},
	)
}

func (rt *requestTx) authReply(subject string, set map[string]interface{}, audiences ...string) (*pb.AuthReply, error) {
	prKey := rt.s.privateKey()
	now := time.Now()
	c := jwt.Claims{
		KeyID: prKey.id,
		Registered: jwt.Registered{
			Issuer:    viper.GetString("JWTIssuer"),
			Subject:   subject,
			Expires:   jwt.NewNumericTime(now.Add(viper.GetDuration("JWTExpiry"))),
			Audiences: audiences,
			Issued:    jwt.NewNumericTime(now),
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

func (rt *requestTx) checkJWT(jwt string) (*jwt.Claims, error) {
	ll := rt.log.WithField("jwt", jwt)
	if jwt == "" {
		ll.WithError(errors.New(errMissingToken)).Warn("checkJWT")
		return nil, status.Error(codes.InvalidArgument, errMissingToken)
	}
	claims, err := rt.s.pubKeys.Check(rt.ctx, []byte(jwt))
	if err == nil {
		ll.WithField("claims", claims).Debug("checkJWT")
		return claims, nil
	}
	ll = ll.WithError(err)
	switch err.Error() {
	case tokens.ErrCommunication:
		ll.Error("checkJWT")
		return nil, status.Error(codes.Internal, "Communication error")
	case tokens.ErrMissingKey:
		ll.Warn("checkJWT")
		return nil, status.Error(codes.NotFound, "Unkown key ID")
	case tokens.ErrKeyVerification:
		ll.Warn("checkJWT")
		return nil, status.Error(codes.Unauthenticated, tokens.ErrKeyVerification)
	case tokens.ErrUnsupportedAlg:
		ll.Warn("checkJWT")
		return nil, status.Error(codes.OutOfRange, tokens.ErrUnsupportedAlg)
	default:
		ll.Error("checkJWT")
		return nil, status.Error(codes.Unknown, "Unknown JWT error")
	}
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

	return user, rt.upsertPassword(user.ID, password)
}

func newPwModel(password string) (*models.Password, error) {
	if password == "" {
		return nil, status.Error(codes.InvalidArgument, errMissingEmailOrName)
	}
	h, err := newHasher()
	if err != nil {
		return nil, status.Error(codes.Internal, errFatal)
	}
	p, err := json.Marshal(h)
	if err != nil {
		return nil, status.Error(codes.Internal, errFatal)
	}
	return &models.Password{
		Hash:  h.hash(password),
		Param: p,
	}, nil
}

func (rt *requestTx) upsertPassword(userID int, password string) error {
	if password == "" {
		rt.log.Warn(errMissingPW)
		return status.Error(codes.InvalidArgument, errMissingPW)
	}
	pwm, err := newPwModel(password)
	if err != nil {
		rt.log.WithError(err).Error("New PW model")
		return status.Error(codes.Internal, errFatal)
	}
	pwm.UserID = userID
	pLog := rt.log.WithField("password_model", pwm)

	if err = pwm.Upsert(
		rt.ctx, rt.tx, true,
		[]string{models.PasswordColumns.UserID},
		boil.Blacklist(models.PasswordColumns.UserID, models.PasswordColumns.CreatedAt),
		boil.Infer(),
	); err != nil {
		pLog.WithError(err).Error("Upsert password")
		return status.Error(codes.Internal, errDB)
	}
	pLog.Debug("Upsert password")
	return nil
}

func (rt *requestTx) dbAuthError(action, entry string, err error) error {
	ll := rt.log.WithError(err)
	switch err {
	case nil:
		return nil
	case sql.ErrNoRows:
		ll.Warnf("%s: %s not found", action, entry)
		return status.Error(codes.Unauthenticated, errCredentials)
	default:
		ll.Error(action)
		return status.Error(codes.Internal, errDB)
	}
}

func (rt *requestTx) findUserByValue(key, value string, columns ...string) (*models.User, error) {
	ll := rt.log.WithFields(logrus.Fields{key: value, "columns": columns})

	qms := []qm.QueryMod{qm.Where(fmt.Sprintf("%s=$1", key), value)}
	// TODO: Test if we can do without this if when columns are nil
	if len(columns) != 0 {
		qms = append(qms, qm.Select(columns...))
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

func (rt *requestTx) checkPassword(hash string, param []byte, password string) error {
	if err := rt.enoughTime(3 * time.Second); err != nil {
		return err
	}
	h := new(argon2hasher)
	ll := rt.log.WithFields(logrus.Fields{"hash": hash, "param": string(param)})
	if err := json.Unmarshal(param, h); err != nil {
		ll.WithError(err).Error("Unmarshal Argon2 params")
		return status.Error(codes.Internal, errFatal)
	}
	ll = ll.WithField("param", h)
	ll.Debug("Unmarshal Argon2 params")
	if hash != h.hash(password) {
		log.WithError(errors.New(errCredentials)).Warn("Password missmatch")
		return status.Error(codes.Unauthenticated, errCredentials)
	}
	return nil
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
	if err = rt.checkPassword(pwm.Hash, pwm.Param, password); err != nil {
		return nil, err
	}
	return user, nil
}

func (rt *requestTx) userExistsByValue(key, value string) (exists bool, err error) {
	_, err = rt.findUserByValue(key, value, models.UserColumns.ID)
	switch err {
	case nil:
		exists = true
	case sql.ErrNoRows:
		rt.log.WithError(err).Debug("userExistsByValue")
		break
	default:
		rt.log.WithError(err).Error("userExistsByValue")
		err = status.Error(codes.Internal, errDB)
	}
	return exists, err
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

func (rt *requestTx) publicUserToken(uuid string) (*pb.AuthReply, error) {
	rt.log = rt.log.WithField("uuid", uuid)
	if uuid == "" {
		rt.log.WithError(errors.New(errMissingUUID)).Warn("publicUserToken")
		return nil, status.Error(codes.InvalidArgument, errMissingUUID)
	}
	rt.log.Debug("publicUserToken")
	return rt.authReply(fmt.Sprintf("public:%s", uuid), nil)
}

func (rt *requestTx) getPubKey(kid int) (*pb.PublicKey, error) {
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
	return &pb.PublicKey{Key: key.PublicKey}, nil
}
