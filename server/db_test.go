package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/spf13/viper"
)

var (
	testCtx context.Context
	db      *sql.DB
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
	tx, err := db.BeginTx(testCtx, nil)
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
	testCtx, cancel = context.WithTimeout(context.Background(), 10*time.Second)

	conf := viper.GetStringMap("pq")
	testDB := conf["dbname"]
	conf["dbname"] = "postgres"

	suDB, err := sql.Open("postgres", connStr(conf))
	if err != nil {
		log.Fatal(err)
	}
	if _, err = suDB.ExecContext(testCtx, fmt.Sprintf("CREATE DATABASE %s;", testDB)); err != nil {
		log.WithError(err).Error("Create testDB failed")
		_, err = suDB.ExecContext(testCtx, fmt.Sprintf("DROP DATABASE %s;", testDB))
		log.WithError(err).Fatal("Drop testDB, terminating")
	}

	conf["dbname"] = testDB
	if db, err = connectDB(); err != nil {
		log.WithError(err).Error("Connect to testDB failed")
		_, err = suDB.ExecContext(testCtx, fmt.Sprintf("DROP DATABASE %s;", testDB))
		log.WithError(err).Fatal("Drop testDB, terminating")
	}
	if err = testData(); err != nil {
		log.WithError(err).Error("Create testdata failed")
		log.WithError(db.Close()).Info("Closed testDB")
		_, err = suDB.ExecContext(testCtx, fmt.Sprintf("DROP DATABASE %s;", testDB))
		log.WithError(err).Fatal("Drop testDB, terminating")
	}

	code := m.Run()

	log.WithError(db.Close()).Info("Closed testDB")
	if _, err = suDB.ExecContext(testCtx, fmt.Sprintf("DROP DATABASE %s;", testDB)); err != nil {
		log.WithError(err).Fatal("Drop testDB failed")
	}
	cancel()
	os.Exit(code)
}

func Test_connString(t *testing.T) {
	type args struct {
		conf map[string]interface{}
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Single",
			args: args{map[string]interface{}{
				"foo": "bar",
			}},
			want: "foo=bar",
		},
		{
			name: "Multiple",
			args: args{map[string]interface{}{
				"foo":   "bar",
				"hello": "world",
			}},
			want: "foo=bar hello=world",
		},
		{
			name: "With int",
			args: args{map[string]interface{}{
				"foo":   "bar",
				"hello": "world",
				"int":   5,
			}},
			want: "foo=bar hello=world int=5",
		},
		{
			name: "Nil",
			want: "",
		},
		{
			name: "Empty",
			args: args{map[string]interface{}{}},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := connStr(tt.args.conf); got != tt.want {
				t.Errorf("connString() = %v, want %v", got, tt.want)
			}
		})
	}
}
