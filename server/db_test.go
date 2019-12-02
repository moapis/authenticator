package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/moapis/authenticator/models"
	"github.com/moapis/multidb"
	migrate "github.com/rubenv/sql-migrate"
	"github.com/spf13/viper"
	"github.com/volatiletech/sqlboiler/boil"
	"golang.org/x/crypto/argon2"
)

var (
	testCtx context.Context
	mdb     *multidb.MultiDB
)

const (
	testSalt = "12345678"
)

func migrations() error {
	m, err := mdb.Master(testCtx)
	if err != nil {
		return err
	}
	migrations := &migrate.FileMigrationSource{
		Dir: "migrations",
	}
	n, err := migrate.Exec(m.DB, "postgres", migrations, migrate.Up)
	if err != nil {
		log.WithError(err).Error("Migrations")
		return err
	}
	log.WithField("n", n).Info("Migrations")
	return nil
}

func userTestData() error {
	tx, err := mdb.MasterTx(testCtx, nil)
	if err != nil {
		log.WithError(err).Error("Obtaining MasterTx")
	}
	defer tx.Rollback()

	groups := []*models.Group{
		{Name: "public"},
		{Name: "user"},
		{Name: "admin"},
	}
	users := []*models.User{
		{
			Email: "foo@bar.com",
			Name:  "foo",
		},
		{
			Email: "mickey@bar.com",
			Name:  "mickey",
		},
		{
			Email: "donald@bar.com",
			Name:  "donald",
		},
		{
			Email: "goofey@bar.com",
			Name:  "goofey",
		},
	}
	insertGroups := true
	for _, u := range users {
		ul := log.WithField("user", u)
		if err = u.Insert(testCtx, tx, boil.Infer()); err != nil {
			ul.WithError(err).Error("Insert user")
			return err
		}
		ul.Debug("Insert user")

		l := ul.WithField("groups", groups)
		if err = u.SetGroups(testCtx, tx, insertGroups, groups...); err != nil {
			l.WithError(err).Error("Add groups")
			return err
		}
		l.Debug("Add groups")
		insertGroups = false

		pw := &models.Password{
			Salt: []byte(testSalt),
			Hash: argon2.IDKey([]byte(u.Name), []byte(testSalt), Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen),
		}
		l = ul.WithField("password", pw)
		if err := u.SetPassword(testCtx, tx, true, pw); err != nil {
			l.WithError(err).Error("Set password")
			return err
		}
		l.Debug("Set password")
	}

	if err = tx.Commit(); err != nil {
		log.WithError(err).Error("tx.Commit()")
		return err
	}
	log.Debug("tx.Commit()")
	return nil
}

func TestMain(m *testing.M) {
	var cancel context.CancelFunc
	testCtx, cancel = context.WithTimeout(context.Background(), 30*time.Minute)

	param := viper.GetStringMapString("DBParams")

	suDB, err := sql.Open("postgres", "host=/run/postgresql dbname=postgres user=postgres sslmode=disable connect_timeout=5")
	if err != nil {
		log.Fatal(err)
	}
	if _, err = suDB.ExecContext(testCtx, fmt.Sprintf("CREATE DATABASE %s;", param["dbname"])); err != nil {
		log.WithError(err).Error("Create testDB failed")
		_, err = suDB.ExecContext(testCtx, fmt.Sprintf("DROP DATABASE %s;", param["dbname"]))
		log.WithError(err).Fatal("Drop testDB, terminating")
	}

	if mdb, err = connectMDB(); err != nil {
		log.WithError(err).Error("Connect to testDB failed")
		_, err = suDB.ExecContext(testCtx, fmt.Sprintf("DROP DATABASE %s;", param["dbname"]))
		log.WithError(err).Fatal("Drop testDB, terminating")
	}
	if err = migrations(); err != nil {
		log.WithError(mdb.Close()).Info("Closed testDB")
		_, err = suDB.ExecContext(testCtx, fmt.Sprintf("DROP DATABASE %s;", param["dbname"]))
		log.WithError(err).Fatal("Drop testDB, terminating")
	}
	if err = userTestData(); err != nil {
		log.WithError(mdb.Close()).Info("Closed testDB")
		_, err = suDB.ExecContext(testCtx, fmt.Sprintf("DROP DATABASE %s;", param["dbname"]))
		log.WithError(err).Fatal("Drop testDB, terminating")
	}

	code := m.Run()

	log.WithError(mdb.Close()).Info("Closed testDB")
	if _, err = suDB.ExecContext(testCtx, fmt.Sprintf("DROP DATABASE %s;", param["dbname"])); err != nil {
		log.WithError(err).Fatal("Drop testDB failed")
	}
	cancel()
	os.Exit(code)
}
