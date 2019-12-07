// Copyright (c) 2019, Mohlmann Solutions SRL. All rights reserved.
// Use of this source code is governed by a License that can be found in the LICENSE file.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/moapis/authenticator/models"
	"github.com/moapis/multidb"
	migrate "github.com/rubenv/sql-migrate"
	"github.com/sirupsen/logrus"
	"github.com/volatiletech/sqlboiler/boil"
	"golang.org/x/crypto/argon2"
)

const (
	testKeyInput = "qwertyuiopasdfghjklzxcvbnm123456"
	testPrivKey  = "qwertyuiopasdfghjklzxcvbnm123456\xda\xf9W\x14\xfcc\xe2\xe5\x1b+i\xa3\n\xbek($\x1e\x18\xc6j/*\x88\xaf\xa7X݉|ֳ"
	testPubKey   = "\xda\xf9W\x14\xfcc\xe2\xe5\x1b+i\xa3\n\xbek($\x1e\x18\xc6j/*\x88\xaf\xa7X݉|ֳ"
)

var (
	testCtx   context.Context
	mdb       *multidb.MultiDB
	tas       *authServer
	testUsers = map[string]*models.User{
		"noGroup": {
			ID:    101,
			Email: "no@group.com",
			Name:  "noGroup",
		},
		"oneGroup": {
			ID:    102,
			Email: "one@group.com",
			Name:  "oneGroup",
		},
		"allGroups": {
			ID:    103,
			Email: "all@groups.com",
			Name:  "allGroups",
		},
	}
	testGroups = []*models.Group{
		{Name: "public"},
		{Name: "user"},
		{Name: "admin"},
	}
)

const (
	testSalt = "12345678"
)

func migrations() {
	migrate.SetTable("migrations")
	m, err := mdb.Master(testCtx)
	if err != nil {
		log.WithError(err).Fatal("migrations()")
	}
	migrations := &migrate.FileMigrationSource{
		Dir: "migrations",
	}
	n, err := migrate.Exec(m.DB, "postgres", migrations, migrate.Up)
	if err != nil {
		log.WithError(err).Fatal("Migrations")
	}
	log.WithField("n", n).Info("Migrations")
}

func migrateDown() {
	m, err := mdb.Master(testCtx)
	if err != nil {
		log.WithError(err).Fatal("migrateDown")
	}
	migrations := &migrate.FileMigrationSource{
		Dir: "migrations",
	}
	n, err := migrate.Exec(m.DB, "postgres", migrations, migrate.Down)
	if err != nil {
		log.WithError(err).Fatal("migrateDown")
	}
	log.WithField("n", n).Info("migrateDown")
}

func userTestData() error {
	tx, err := mdb.MasterTx(testCtx, nil)
	if err != nil {
		log.WithError(err).Error("Obtaining MasterTx")
	}
	defer tx.Rollback()

	for _, g := range testGroups {
		gl := log.WithField("group", g)
		if err = g.Insert(testCtx, tx, boil.Infer()); err != nil {
			gl.WithError(err).Error("Insert group")
			return err
		}
		gl.Debug("Insert group")
	}
	for _, u := range testUsers {
		ul := log.WithField("user", u)
		if err = u.Insert(testCtx, tx, boil.Infer()); err != nil {
			ul.WithError(err).Error("Insert user")
			return err
		}
		ul.Debug("Insert user")

		pw := &models.Password{
			Salt: []byte(testSalt),
			Hash: argon2.IDKey([]byte(u.Name), []byte(testSalt), Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen),
		}
		ul = ul.WithField("password", pw)
		if err := u.SetPassword(testCtx, tx, true, pw); err != nil {
			ul.WithError(err).Error("Set password")
			return err
		}
		ul.Debug("Set password")
	}
	if err = testUsers["oneGroup"].AddGroups(testCtx, tx, false, testGroups[0]); err != nil {
		log.WithError(err).Error("AddGroups one")
	}
	if err = testUsers["allGroups"].AddGroups(testCtx, tx, false, testGroups...); err != nil {
		log.WithError(err).Error("AddGroups all")
	}

	if err = tx.Commit(); err != nil {
		log.WithError(err).Error("tx.Commit()")
		return err
	}
	log.Debug("tx.Commit()")
	return nil
}

func jwtTestData() error {
	tx, err := mdb.MasterTx(testCtx, nil)
	if err != nil {
		log.WithError(err).Error("Obtaining MasterTx")
	}
	defer tx.Rollback()

	token := &models.JWTKey{
		ID:        10,
		PublicKey: []byte(testPubKey),
	}
	log := log.WithField("token", token)

	if err = token.Insert(testCtx, tx, boil.Infer()); err != nil {
		log.WithError(err).Error("token.Insert()")
		return err
	}
	log.Debug("token.Insert()")
	if err = tx.Commit(); err != nil {
		log.WithError(err).Error("tx.Commit()")
		return err
	}
	log.Debug("tx.Commit()")
	return nil
}

func TestMain(m *testing.M) {
	c, err := configure(Default)
	if err != nil {
		log.WithError(err).Fatal("configure()")
	}

	var cancel context.CancelFunc
	testCtx, cancel = context.WithTimeout(context.Background(), 30*time.Second)

	mdb, err = c.MultiDB.Open()
	if err != nil {
		log.WithError(err).Fatal("mdb.Open()")
	}

	migrations()
	if err = userTestData(); err != nil {
		migrateDown()
		log.WithError(err).Fatal("userTestData()")
	}
	if err = jwtTestData(); err != nil {
		migrateDown()
		log.WithError(err).Fatal("jwtTestData()")
	}

	tas = &authServer{
		log:     logrus.NewEntry(log),
		conf:    c,
		mdb:     mdb,
		privKey: privateKey{"10", []byte(testPrivKey)},
	}

	code := m.Run()

	migrateDown()
	cancel()
	os.Exit(code)
}
