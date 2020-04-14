FROM golang:1.14 AS build

COPY . /go/src/github.com/moapis/authenticator
WORKDIR /go/src/github.com/moapis/authenticator/cmd/httpauth
RUN go build

FROM debian:buster-slim

COPY cmd/httpauth/static/ /static
COPY cmd/httpauth/templates/ /templates
COPY cmd/httpauth/config/docker.json /docker.json

COPY --from=build /go/src/github.com/moapis/authenticator/cmd/httpauth/httpauth /httpauth

ENTRYPOINT [ "/httpauth" ]

CMD [ "-config", "/docker.json" ]