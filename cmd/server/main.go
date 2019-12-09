// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/rand"
	"os"
	"os/signal"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

var (
	log *logrus.Logger
)

// LogLevel used for logrus
type LogLevel string

const (
	// PanicLevel sets logrus level to panic
	PanicLevel LogLevel = "panic"
	// FatalLevel sets logrus level to fatal
	FatalLevel LogLevel = "fatal"
	// ErrorLevel sets logrus level to error
	ErrorLevel LogLevel = "error"
	// WarnLevel sets logrus level to warn
	WarnLevel LogLevel = "warn"
	// InfoLevel sets logrus level to info
	InfoLevel LogLevel = "info"
	// DebugLevel sets logrus level to debug
	DebugLevel LogLevel = "debug"
	// TraceLevel sets logrus level to trace
	TraceLevel LogLevel = "trace"
)

func init() {
	log = logrus.New()
	log.SetLevel(logrus.InfoLevel)
}

func main() {
	c, err := configure(Default)
	if err != nil {
		log.WithError(err).Fatal("configure()")
	}
	opts, err := c.grpcOpts()
	if err != nil {
		log.WithError(err).Fatal("grpcOpts()")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s, err := c.newAuthServer(ctx, rand.Reader)
	if err != nil {
		log.WithError(err).Fatal("newAuthServer")
	}

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, os.Interrupt)

	gs, ec := c.listenAndServe(s, opts...)
	select {
	case sig := <-sc:
		log.WithField("signal", sig).Info("Shutdown")
		gs.GracefulStop()
	case err = <-ec:
		log.WithError(err).Fatal("Shutdown")
	}
}

var middleware []grpc.UnaryServerInterceptor

func middlewareInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	return handler(ctx, req)
}
