package main

import (
	"time"

	_ "github.com/lib/pq"
	"github.com/moapis/multidb"
	"github.com/moapis/multidb/drivers/postgresql"
	"github.com/spf13/viper"
)

func init() {
	viper.SetDefault("DBHosts", map[string]uint16{"/run/postgresql": 5432})
	viper.SetDefault("DBParams", map[string]string{
		"dbname":          "authenticator_test",
		"user":            "postgres",
		"password":        "",
		"sslmode":         "disable",
		"connect_timeout": "30",
	})
	viper.SetDefault("DBRoutines", 3)
}

func parseDBHosts() []postgresql.Host {
	var hosts []postgresql.Host
	hm := viper.Get("DBHosts").(map[string]uint16)
	for addr, port := range hm {
		host := postgresql.Host{
			Addr: addr,
			Port: port,
		}
		hosts = append(hosts, host)
	}
	return hosts
}

func connectMDB() (*multidb.MultiDB, error) {
	c := multidb.Config{
		DBConf: postgresql.Config{
			Hosts:  parseDBHosts(),
			Params: viper.GetStringMapString("DBParams"),
		},
		StatsLen:      100,
		MaxFails:      10,
		ReconnectWait: 10 * time.Second,
	}
	// Connect to all specified DB Hosts
	return c.Open()
}