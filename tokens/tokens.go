// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package tokens

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/friendsofgo/errors"
	pb "github.com/moapis/authenticator/pb"
	"github.com/pascaldekloe/jwt"
)

// KeyClientCache gets public keys from the Authenticator gRPC server
// Public keys are cached for reuse.
type KeyClientCache struct {
	Client pb.AuthenticatorClient
	keys   map[int32][]byte
	mtx    sync.RWMutex
}

const (
	// ErrCommunication is returned when the gRPC client call returns an error
	ErrCommunication = "gRPC communication error"
	// ErrMissingKey is returned when a gRCP client response does not contan a key
	ErrMissingKey = "Missing key in gRPC response"
	// ErrUnsupportedAlg is returned if the JWT is sigined with an unsupported algoritm
	ErrUnsupportedAlg = "Unsupported algoritm"
	// ErrKeyVerification is returned when JWT did not appear to be valid
	ErrKeyVerification = "Key verification error"
)

// Get key from cache
func (k *KeyClientCache) Get(kid int32) ([]byte, bool) {
	k.mtx.RLock()
	key, ok := k.keys[kid]
	k.mtx.RUnlock()
	return key, ok
}

// Set key to cache. Existing key with same ID will be overwritten.
func (k *KeyClientCache) Set(kid int32, key []byte) {
	k.mtx.Lock()
	if k.keys == nil {
		k.keys = make(map[int32][]byte)
	}
	k.keys[kid] = key
	k.mtx.Unlock()
}

// edDSACheck is a wrapper for jwt.EdDSACheck() to return a proper error
func edDSACheck(token []byte, key ed25519.PublicKey) (*jwt.Claims, error) {
	claims, err := jwt.EdDSACheck(token, key)
	switch err.(type) {
	case nil:
		return claims, err
	case jwt.AlgError:
		return nil, errors.WithMessage(err, ErrUnsupportedAlg)
	default:
		return nil, errors.WithMessage(err, ErrKeyVerification)
	}
}

// Retrieve a key over gRPC Client.
// After succesful retrieval, the key is Set to the cache
func (k *KeyClientCache) Retrieve(ctx context.Context, kid int32) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pkl, err := k.Client.GetPubKey(ctx, &pb.KeyID{Kid: kid})
	if err != nil {
		return nil, errors.WithMessage(err, ErrCommunication)
	}
	key := pkl.GetKey()
	if key == nil {
		return nil, fmt.Errorf(ErrMissingKey)
	}
	k.Set(kid, key)
	return key, nil
}

func (k *KeyClientCache) getOrRetrieve(ctx context.Context, kid int32) ([]byte, error) {
	if key, ok := k.Get(kid); ok {
		return key, nil
	}
	return k.Retrieve(ctx, kid)
}

var jwtSeperator = []byte(".")

// ParseJWTHeader checks is the Alg field is supported and returns the Kid as an int.
func ParseJWTHeader(token []byte) (int, error) {
	var h struct {
		Alg string // algorithm
		Kid string // key identifier
	}
	if err := json.Unmarshal(bytes.Split(token, jwtSeperator)[0], &h); err != nil {
		return 0, errors.WithMessage(err, ErrKeyVerification)
	}
	if h.Alg != jwt.EdDSA {
		return 0, errors.New(ErrUnsupportedAlg)
	}
	kid, err := strconv.ParseInt(h.Kid, 10, 32)
	if err != nil {
		return 0, errors.WithMessage(err, ErrKeyVerification)
	}
	return int(kid), err
}

// Check if the JWT is valid and return the Claims if so.
// If the key is not in the cache, it will be fetched through the client before checking.
// Typical errors can by of grpc/status or Verfication error
func (k *KeyClientCache) Check(ctx context.Context, token []byte) (*jwt.Claims, error) {
	kid, err := ParseJWTHeader(token)
	if err != nil {
		return nil, err
	}
	key, err := k.getOrRetrieve(ctx, int32(kid))
	if err != nil {
		return nil, err
	}
	return jwt.EdDSACheck(token, key)
}
