package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/moapis/authenticator/models"
)

const (
	testKeyInput = "qwertyuiopasdfghjklzxcvbnm123456"
	testPrivKey  = "qwertyuiopasdfghjklzxcvbnm123456\xda\xf9W\x14\xfcc\xe2\xe5\x1b+i\xa3\n\xbek($\x1e\x18\xc6j/*\x88\xaf\xa7X݉|ֳ"
	testPubKey   = "\xda\xf9W\x14\xfcc\xe2\xe5\x1b+i\xa3\n\xbek($\x1e\x18\xc6j/*\x88\xaf\xa7X݉|ֳ"
)

func Test_authServer_updateKeyPair(t *testing.T) {
	errDB, err := connectDB()
	if err != nil {
		t.Fatal(err)
	}
	if err = errDB.Close(); err != nil {
		t.Fatal(err)
	}
	type fields struct {
		db *sql.DB
	}
	type result struct {
		privKey privateKey
		pubKey  ed25519.PublicKey
	}
	type args struct {
		ctx context.Context
		r   io.Reader
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    result
		wantErr bool
	}{
		{
			name: "Defined input reader",
			fields: fields{
				db: db,
			},
			args: args{
				testCtx,
				strings.NewReader(testKeyInput),
			},
			want: result{
				privKey: privateKey{
					id:  "1",
					key: []byte(testPrivKey),
				},
				pubKey: []byte(testPubKey),
			},
		},
		{
			name: "Defunct input reader",
			fields: fields{
				db: db,
			},
			args: args{
				testCtx,
				strings.NewReader(""),
			},
			wantErr: true,
		},
		{
			name: "DB error",
			fields: fields{
				db: errDB,
			},
			args: args{
				testCtx,
				strings.NewReader(testKeyInput),
			},
			wantErr: true,
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &authServer{
				db: tt.fields.db,
			}
			err := s.updateKeyPair(tt.args.ctx, tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.updateKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got := result{
				privKey: s.privKey,
			}
			if !tt.wantErr {
				m, err := models.FindJWTKey(testCtx, db, i+1, "public_key")
				if err != nil {
					t.Fatal(err)
				}
				got.pubKey = m.PublicKey
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authServer.updateKeyPair() = \n%v\nwant\n %v", got, tt.want)
			}
			s.keyMtx.Lock() // Will hang if mutex was not proberly cleared
			s.keyMtx.Unlock()
		})
	}
}

func Test_authServer_privateKey(t *testing.T) {
	type fields struct {
		privKey privateKey
	}
	tests := []struct {
		name   string
		fields fields
		want   privateKey
	}{
		{
			name: "Empty key",
		},
		{
			name: "Predefined key",
			fields: fields{
				privKey: privateKey{
					id:  "foo",
					key: []byte(testPrivKey),
				},
			},
			want: privateKey{
				id:  "foo",
				key: []byte(testPrivKey),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &authServer{
				privKey: tt.fields.privKey,
			}
			if got := s.privateKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authServer.privateKey() = %v, want %v", got, tt.want)
			}
			s.keyMtx.Lock() // Will hang if mutex was not proberly cleared
			s.keyMtx.Unlock()
		})
	}
}
