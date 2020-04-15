FROM golang:1.14 AS build

COPY . /go/src/github.com/moapis/authenticator
WORKDIR /go/src/github.com/moapis/authenticator/cmd/admin
RUN go build

FROM debian:buster-slim

COPY cmd/admin/AdminLTE/dist /AdminLTE/dist
COPY cmd/admin/AdminLTE/plugins /AdminLTE/plugins
COPY cmd/admin/static/ /static
COPY cmd/admin/templates/ /templates
COPY cmd/admin/config/docker.json /docker.json

COPY --from=build /go/src/github.com/moapis/authenticator/cmd/admin/admin /admin

ENTRYPOINT [ "/admin" ]

CMD [ "-config", "/docker.json" ]