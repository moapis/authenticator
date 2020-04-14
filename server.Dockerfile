FROM golang:1.14 AS build

COPY . /go/src/github.com/moapis/authenticator
WORKDIR /go/src/github.com/moapis/authenticator/cmd/server
RUN go build

FROM debian:buster-slim

RUN apt-get update && \
    apt-get install -y ca-certificates

COPY cmd/server/templates/ /templates
COPY cmd/server/config/docker.json /docker.json

COPY --from=build /go/src/github.com/moapis/authenticator/cmd/server/server /server

ENTRYPOINT [ "/server" ]

CMD [ "-config", "/docker.json" ]
