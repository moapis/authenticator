package main

import (
	"crypto/rand"

	"github.com/spf13/viper"
	"golang.org/x/crypto/argon2"
)

func init() {
	viper.SetDefault("pwSaltLen", 8)
	viper.SetDefault("argon2Time", 1)
	viper.SetDefault("argon2Memory", 64*1024)
	viper.SetDefault("argon2Threads", 2)
	viper.SetDefault("argon2KeyLen", 32)
}

type argon2hasher struct {
	time, memory, keyLen uint32
	threads              uint8
	salt                 []byte
}

func newHasher() (*argon2hasher, error) {
	salt := make([]byte, viper.GetUint("pwSaltLen"))
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return &argon2hasher{
		time:    viper.GetUint32("argon2Time"),
		memory:  viper.GetUint32("argon2Memory"),
		threads: uint8(viper.GetUint("argon2Threads")),
		keyLen:  viper.GetUint32("argon2KeyLen"),
	}, nil
}

func (h *argon2hasher) hash(password string) string {
	return string(argon2.IDKey([]byte(password), h.salt, h.time, h.memory, h.threads, h.keyLen))
}
