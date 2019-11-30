package main

import (
	"context"
	"reflect"
	"testing"
	"time"

	pb "github.com/moapis/authenticator/pb"
	"github.com/moapis/multidb"
	"github.com/sirupsen/logrus"
)

func Test_authServer_newTx(t *testing.T) {
	ex, cancel := context.WithTimeout(context.Background(), -1)
	defer cancel()
	type fields struct {
		mdb *multidb.MultiDB
		log *logrus.Entry
	}
	type args struct {
		ctx    context.Context
		method string
		master bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			"Slave node",
			fields{
				mdb: mdb,
				log: logrus.NewEntry(log),
			},
			args{
				ctx:    context.Background(),
				method: "some",
				master: false,
			},
			false,
		},
		{
			"Master node",
			fields{
				mdb: mdb,
				log: logrus.NewEntry(log),
			},
			args{
				ctx:    context.Background(),
				method: "some",
				master: true,
			},
			false,
		},
		{
			"Context error",
			fields{
				mdb: mdb,
				log: logrus.NewEntry(log),
			},
			args{
				ctx:    ex,
				method: "some",
				master: false,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &authServer{
				mdb: tt.fields.mdb,
				log: tt.fields.log,
			}
			got, err := s.newTx(tt.args.ctx, tt.args.method, tt.args.master)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.newTx() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && (got == nil || got.tx == nil || got.ctx == nil || got.cancel == nil || got.log == nil || got.s == nil) {
				t.Errorf("authServer.newTx() = %v, unexpected nil field", got)
			}
			if !tt.wantErr {
				if err = got.commit(); err != nil {
					t.Fatal(err)
				}
				got.done()
			}
		})
	}
}

func Test_requestTx_enoughTime(t *testing.T) {
	ex, cancel := context.WithTimeout(context.Background(), -1)
	defer cancel()
	short, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tests := []struct {
		name    string
		ctx     context.Context
		need    time.Duration
		wantErr bool
	}{
		{
			"Expired context",
			ex,
			0,
			true,
		},
		{
			"Enough time",
			short,
			time.Millisecond,
			false,
		},
		{
			"Skip check",
			short,
			time.Millisecond,
			false,
		},
		{
			"Not enough time",
			short,
			2 * time.Second,
			true,
		},
		{
			"No deadline",
			context.Background(),
			time.Millisecond,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &requestTx{
				ctx: tt.ctx,
				log: logrus.NewEntry(log),
			}
			if err := rt.enoughTime(tt.need); (err != nil) != tt.wantErr {
				t.Errorf("requestTx.enoughTime() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func newTestTx() (*requestTx, error) {
	s := &authServer{
		mdb: mdb,
		log: logrus.NewEntry(log),
		privKey: privateKey{
			id:  "10",
			key: []byte(testPrivKey),
		},
	}
	return s.newTx(context.Background(), "testing", false)
}

func Test_requestTx_done_commit(t *testing.T) {
	tx, err := newTestTx()
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.commit(); err != nil {
		t.Errorf("requestTx.commit() error = %v, wantErr %v", err, false)
	}
	if err = tx.commit(); err == nil {
		t.Errorf("requestTx.commit() error = %v, wantErr %v", err, true)
	}
	tx.done()
	tx, err = newTestTx()
	if err != nil {
		t.Fatal(err)
	}
	tx.done()
}

func Test_requestTx_authReply(t *testing.T) {
	type args struct {
		subject   string
		issued    time.Time
		set       map[string]interface{}
		audiences []string
	}
	tests := []struct {
		name    string
		args    args
		want    *pb.AuthReply
		wantErr bool
	}{
		{
			"Fixed key/time",
			args{
				subject:   "testuser",
				issued:    time.Unix(123, 456),
				set:       map[string]interface{}{"some": 1},
				audiences: []string{"foo", "bar"},
			},
			&pb.AuthReply{
				Jwt: "eyJhbGciOiJFZERTQSIsImtpZCI6IjEwIn0.eyJhdWQiOlsiZm9vIiwiYmFyIl0sImV4cCI6ODY1MjMuMDAwMDAwNDU2LCJpYXQiOjEyMy4wMDAwMDA0NTYsImlzcyI6ImxvY2FsaG9zdCIsInNvbWUiOjEsInN1YiI6InRlc3R1c2VyIn0.Ox2PHwJ5Q7u4P2n5y1PZ630hm0J0N4yam14GA4-NSgn-Ak3L9Au2a8GHzN-AoQGbREJA1GDdIwGWIoGS3TthBQ",
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt, err := newTestTx()
			if err != nil {
				t.Fatal(err)
			}
			defer rt.done()
			got, err := rt.authReply(tt.args.subject, tt.args.issued, tt.args.set, tt.args.audiences...)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestTx.authReply() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("requestTx.authReply() = %v, want %v", got, tt.want)
			}
		})
	}
}
