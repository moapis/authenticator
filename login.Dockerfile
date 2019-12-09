FROM golang:1.13 AS build

COPY . /go/src/github.com/moapis/authenticator
WORKDIR /go/src/github.com/moapis/authenticator/cmd/login
RUN go build -v

FROM debian:buster-slim

COPY --from=build /go/src/github.com/moapis/authenticator/cmd/login/templates/ /templates
COPY --from=build /go/src/github.com/moapis/authenticator/cmd/login/login /login
ENTRYPOINT [ "/login", "-template=/templates/login.html" ]