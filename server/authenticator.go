package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"io"
	"strconv"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/moapis/authenticator/models"
	pb "github.com/moapis/authenticator/pb"
	"github.com/moapis/authenticator/tokens"
	"github.com/volatiletech/sqlboiler/boil"
)

type privateKey struct {
	id  string
	key ed25519.PrivateKey
}

type authServer struct {
	pb.UnimplementedAuthenticatorServer
	db *sql.DB

	privKey privateKey
	keyMtx  sync.RWMutex //Protects privKey during updates

	pubKeys *tokens.KeyClientCache

	log *logrus.Entry
}

func newAuthServer() (*authServer, error) {
	s := &authServer{
		pubKeys: new(tokens.KeyClientCache),
		log:     logrus.WithField("server", "Authenticator"),
	}
	log.SetLevel(logrus.DebugLevel)
	var err error
	if s.db, err = connectDB(); err != nil {
		return nil, err
	}
	if err = s.updateKeyPair(context.Background(), rand.Reader); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *authServer) updateKeyPair(ctx context.Context, r io.Reader) error {
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return err
	}
	m := &models.JWTKey{
		PublicKey: pub,
	}
	if err = m.Insert(ctx, s.db, boil.Infer()); err != nil {
		return err
	}
	pk := privateKey{
		id:  strconv.Itoa(m.ID),
		key: priv,
	}

	s.keyMtx.Lock()
	s.privKey = pk
	s.keyMtx.Unlock()

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
	errMissingUUID        = "UUID missing"
	errMissingKeyID       = "Public key ID missing"
	errKeyNotFound        = "Key ID not found"
	errFatal              = "Fatal I/O error"
	errDB                 = "Database error"
	errMailer             = "Failed to send verification mail"
)

func (s *authServer) RegisterPwUser(ctx context.Context, pu *pb.NewPwUser) (*pb.AuthReply, error) {
	rt, err := s.newTx(ctx, "RegisterPwUser")
	if err != nil {
		return nil, err
	}
	defer rt.done()

	user, err := rt.insertPwUser(pu.GetEmail(), pu.GetName(), pu.GetPassword())
	if err != nil {
		return nil, err
	}

	/*
		action = "Send verification mail"
		if err := sendVerificationMail(ctx); err != nil {
			logger.WithError(err).Error(action)
			return nil, status.Error(codes.Internal, errMailer)
		}
		logger.Debug(action)
	*/
	if err = rt.commit(); err != nil {
		return nil, err
	}
	return rt.userAuthReply(user)
}

func (s *authServer) AuthenticatePwUser(ctx context.Context, up *pb.UserPassword) (*pb.AuthReply, error) {
	rt, err := s.newTx(ctx, "AuthenticatePwUser")
	if err != nil {
		return nil, err
	}
	defer rt.done()

	user, err := rt.authenticatePwUser(up.GetEmail(), up.GetName(), up.GetPassword())
	if err != nil {
		return nil, err
	}

	return rt.userAuthReply(user)
}

func (s *authServer) ChangeUserPw(ctx context.Context, up *pb.NewUserPassword) (*pb.ChangePwReply, error) {
	rt, err := s.newTx(ctx, "ChangeUserPw")
	if err != nil {
		return nil, err
	}
	defer rt.done()

	user, err := rt.authenticatePwUser(up.GetEmail(), up.GetName(), up.GetOldPassword())
	if err != nil {
		return nil, err
	}
	if err = rt.upsertPassword(user.ID, up.GetNewPassword()); err != nil {
		return nil, err
	}
	if err = rt.commit(); err != nil {
		return nil, err
	}
	return &pb.ChangePwReply{Success: true}, nil
}

const (
	userExistsQuery = "select exists (select true from users where %s=$1);"
)

func (s *authServer) CheckUserExists(ctx context.Context, ud *pb.UserData) (*pb.Exists, error) {
	rt, err := s.newTx(ctx, "ChangeCheckUserExistsUserPw")
	if err != nil {
		return nil, err
	}
	defer rt.done()
	return rt.checkUserExists(ud.GetEmail(), ud.GetName())
}

func (s *authServer) RefreshToken(ctx context.Context, old *pb.AuthReply) (*pb.AuthReply, error) {
	rt, err := s.newTx(ctx, "RefreshToken")
	if err != nil {
		return nil, err
	}
	defer rt.done()
	claims, err := rt.checkJWT(old.GetJwt())
	if err != nil {
		return nil, err
	}
	user, err := rt.findUserByEmailOrName("", claims.Subject)
	if err != nil {
		return nil, err
	}
	return rt.userAuthReply(user)
}

func (s *authServer) PublicUserToken(ctx context.Context, pu *pb.PublicUser) (*pb.AuthReply, error) {
	rt, err := s.newTx(ctx, "PublicUserToken")
	if err != nil {
		return nil, err
	}
	defer rt.done()
	return rt.publicUserToken(pu.GetUuid())
}

func (s *authServer) GetPubKey(ctx context.Context, k *pb.KeyID) (*pb.PublicKey, error) {
	rt, err := s.newTx(ctx, "GetPubKey")
	if err != nil {
		return nil, err
	}
	return rt.getPubKey(int(k.GetKid()))
}
