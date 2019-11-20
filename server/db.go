package main

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"

	_ "github.com/lib/pq"
	"github.com/spf13/viper"
)

func init() {
	viper.SetDefault(
		"pq",
		map[string]interface{}{
			"dbname":          "authenticator_test",
			"user":            "postgres",
			"host":            "/run/postgresql",
			"port":            5432,
			"sslmode":         "disable",
			"connect_timeout": 60,
		},
	)
}

func connectDB() (*sql.DB, error) {
	conf := viper.GetStringMap("pq")
	log.WithFields(conf).Debug("Connecting to database")
	return sql.Open("postgres", connStr(conf))
}

func connStr(conf map[string]interface{}) string {
	if conf == nil {
		return ""
	}
	// Sorting of map needed for unit tests
	// Also, filters out empty entries
	keys := make([]string, 0, len(conf))
	for k, v := range conf {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	nodes := make([]string, 0, len(keys))
	for _, key := range keys {
		nodes = append(nodes, fmt.Sprintf("%s=%v", key, conf[key]))
	}
	s := strings.Join(nodes, " ")
	log.WithField("string", s).Debug("Connection string")
	return s
}
