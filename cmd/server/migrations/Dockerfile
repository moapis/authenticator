FROM golang:1.13 AS build

RUN go get -v github.com/rubenv/sql-migrate/...

FROM debian:buster-slim

RUN apt-get update && \
    apt-get install -y ca-certificates

COPY --from=build /go/bin/sql-migrate /usr/local/bin/sql-migrate
WORKDIR /migrations
COPY . .

ENV DB_HOST=postgres
ENV DB_NAME=authenticator
ENV DB_USER=postgres
ENV DB_PASSWORD=foobar
ENV DB_SSLMODE=require

ENTRYPOINT [ "sql-migrate" ]