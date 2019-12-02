// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	pb "github.com/moapis/authenticator/pb"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var log *logrus.Logger

func init() {
	viper.SetDefault("Host", "localhost")
	viper.SetDefault("Port", 5050)
	viper.SetDefault("TLSPem", "authenticator.pem")
	viper.SetDefault("TLSKey", "authenticator.key")
	viper.SetDefault("TLS", false)
	log = logrus.New()
	log.SetLevel(logrus.DebugLevel)
}

func main() {
	s := grpc.NewServer(setOpts()...)
	pb.RegisterAuthenticatorServer(s, new(authServer))
	log.WithField("grpc", s.GetServiceInfo()).Debug("Registered services")

	host, port := viper.GetString("Host"), viper.GetInt32("Port")
	logger := log.WithFields(logrus.Fields{"host": host, "port": port})
	logger.Info("Starting server")
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		logger.WithError(err).Fatal("Failed to listen")
	}
	if err = s.Serve(lis); err != nil {
		logger.WithError(err).Fatal("Failed to serve")
	}
}

func setOpts() []grpc.ServerOption {
	opts := []grpc.ServerOption{
		grpc.UnaryInterceptor(middlewareInterceptor),
	}
	if viper.GetBool("TLS") {
		pem, key := viper.GetString("TLSPem"), viper.GetString("TLSKey")
		cert, err := tls.LoadX509KeyPair(pem, key)
		if err != nil {
			log.WithFields(logrus.Fields{"TLSPem": pem, "TLSKey": key}).WithError(err).Fatal("Failed to set TLS opts")
		}
		opts = append(opts, grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	}
	return opts
}

var middleware []grpc.UnaryServerInterceptor

func middlewareInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	return handler(ctx, req)
}
