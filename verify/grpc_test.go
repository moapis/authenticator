package verify

import (
	"context"
	"log"
	"net"
	"os"
	"testing"

	auth "github.com/moapis/authenticator"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type testAuthenticatorServer struct {
	*auth.UnimplementedAuthenticatorServer
}

var (
	testKeyReponse = []byte("found-key")
	testKeyCached  = []byte("foobar")
)

func (*testAuthenticatorServer) GetPubKey(ctx context.Context, req *auth.KeyID) (*auth.PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	kid := req.GetKid()
	switch kid {
	case 0:
		return nil, status.Error(codes.InvalidArgument, "Missing key ID")
	case 22:
		return &auth.PublicKey{Key: testKeyReponse}, nil
	case 33:
		return &auth.PublicKey{Key: testKeyReponse}, nil
	default:
		return &auth.PublicKey{}, nil
	}
}

var testVerificator *Verificator

const testAddr = "127.0.0.1:10000"

func TestMain(m *testing.M) {
	s := grpc.NewServer()
	auth.RegisterAuthenticatorServer(s, new(testAuthenticatorServer))
	lis, err := net.Listen("tcp", testAddr)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		if err = s.Serve(lis); err != nil {
			log.Fatal(err)
		}
	}()

	cc, err := grpc.Dial(testAddr, grpc.WithBlock(), grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	testVerificator = &Verificator{
		Client:    auth.NewAuthenticatorClient(cc),
		Audiences: []string{"tester"},
		keys:      map[int32][]byte{10: []byte(testPubKey)},
	}

	c := m.Run()
	if err = cc.Close(); err != nil {
		log.Fatal(err)
	}

	s.Stop()
	os.Exit(c)
}
