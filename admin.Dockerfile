FROM golang:1.13 AS build

COPY . /go/src/github.com/moapis/authenticator
WORKDIR /go/src/github.com/moapis/authenticator/cmd/admin
RUN go build -v

FROM debian:buster-slim

COPY --from=build /go/src/github.com/moapis/authenticator/cmd/admin/templates/ /templates
COPY --from=build /go/src/github.com/moapis/authenticator/cmd/admin/admin /admin
ENTRYPOINT [ "/admin" ]