package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/moapis/multidb"
	"github.com/spf13/viper"
)

var (
	testCtx context.Context
	mdb     *multidb.MultiDB
)

func testData() error {
	queries := []string{
		`CREATE TABLE public.jwt_keys
		(
			id serial NOT NULL PRIMARY KEY,
			public_key bytea NOT NULL,
			created_at timestamp with time zone NOT NULL,
			UNIQUE (public_key)
		);`,
	}
	tx, err := mdb.MasterTx(testCtx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range queries {
		if _, err := tx.ExecContext(testCtx, q); err != nil {
			return err
		}
	}
	return tx.Commit()
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
	if err = testData(); err != nil {
		log.WithError(err).Error("Create testdata failed")
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
