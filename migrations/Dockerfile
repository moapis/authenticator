FROM golang:1.14 AS build

RUN go get github.com/rubenv/sql-migrate/sql-migrate

FROM debian:buster-slim

RUN apt-get update && \
    apt-get install -y ca-certificates

COPY --from=build /go/bin/sql-migrate /usr/local/bin/sql-migrate
WORKDIR /migrations
COPY . .

ENV DB_HOST=pg
ENV DB_NAME=authenticator
ENV DB_USER=authenticator
ENV DB_PASSWORD=Simple
ENV DB_SSLMODE=disable

ENTRYPOINT [ "sql-migrate" ]