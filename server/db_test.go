package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/moapis/multidb"
	migrate "github.com/rubenv/sql-migrate"
	"github.com/spf13/viper"
)

var (
	testCtx context.Context
	mdb     *multidb.MultiDB
)

func migrations() error {
	m, err := mdb.Master(testCtx)
	if err != nil {
		return err
	}
	migrations := &migrate.FileMigrationSource{
		Dir: "migrations/tests",
	}
	n, err := migrate.Exec(m.DB, "postgres", migrations, migrate.Up)
	if err != nil {
		log.WithError(err).Error("Migrations")
		return err
	}
	log.WithField("n", n).Info("Migrations")
	return nil
}

func TestMain(m *testing.M) {
	var cancel context.CancelFunc
	testCtx, cancel = context.WithTimeout(context.Background(), 30*time.Second)

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

	code := m.Run()

	log.WithError(mdb.Close()).Info("Closed testDB")
	if _, err = suDB.ExecContext(testCtx, fmt.Sprintf("DROP DATABASE %s;", param["dbname"])); err != nil {
		log.WithError(err).Fatal("Drop testDB failed")
	}
	cancel()
	os.Exit(code)
}
