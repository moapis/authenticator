package verify

import (
	"context"
	"log"
	"net"
	"os"
	"testing"

	pb "github.com/moapis/authenticator/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type testAuthenticatorServer struct {
	*pb.UnimplementedAuthenticatorServer
}

var (
	testKeyReponse = []byte("found-key")
	testKeyCached  = []byte("foobar")
)

func (*testAuthenticatorServer) GetPubKey(ctx context.Context, req *pb.KeyID) (*pb.PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	kid := req.GetKid()
	switch kid {
	case 0:
		return nil, status.Error(codes.InvalidArgument, "Missing key ID")
	case 22:
		return &pb.PublicKey{Key: testKeyReponse}, nil
	case 33:
		return &pb.PublicKey{Key: testKeyReponse}, nil
	default:
		return &pb.PublicKey{}, nil
	}
}

var testVerificator *Verificator

const testAddr = "127.0.0.1:8765"

func TestMain(m *testing.M) {
	s := grpc.NewServer()
	pb.RegisterAuthenticatorServer(s, new(testAuthenticatorServer))
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
		Client: pb.NewAuthenticatorClient(cc),
		keys:   map[int32][]byte{10: []byte(testPubKey)},
	}

	c := m.Run()
	if err = cc.Close(); err != nil {
		log.Fatal(err)
	}

	s.Stop()
	os.Exit(c)
}
