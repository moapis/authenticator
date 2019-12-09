FROM golang:1.13 AS build

COPY . /go/src/github.com/moapis/authenticator
WORKDIR /go/src/github.com/moapis/authenticator/cmd/server
RUN go build -v

FROM debian:buster-slim

RUN apt-get update && \
    apt-get install -y ca-certificates

COPY --from=build /go/src/github.com/moapis/authenticator/cmd/server /server