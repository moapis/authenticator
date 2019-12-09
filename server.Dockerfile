FROM golang:1.13

WORKDIR /go/src/github.com/moapis/authenticator

COPY go.mod go.sum ./
RUN go mod download

COPY pb/*.go pb/
COPY verify/*.go verify/
COPY cmd/server/*.go cmd/server/

WORKDIR /go/src/github.com/moapis/authenticator/cmd/server
RUN go build -v