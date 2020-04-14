#!/bin/bash

set -e

TAG="$1"
if [ -n "$TRAVIS_TAG" ]; then
    TAG="${TRAVIS_TAG#v}"
fi
export TAG="${TAG}"

docker build -t "moapis/authenticator-server:${TAG}" -f server.Dockerfile .
docker build -t "moapis/authenticator-httpauth:${TAG}" -f httpauth.Dockerfile .
docker build -t "moapis/authenticator-admin:${TAG}" -f admin.Dockerfile .
docker build -t "moapis/authenticator-migrations:${TAG}" migrations

docker push "moapis/authenticator-server:${TAG}"
docker push "moapis/authenticator-httpauth:${TAG}"
docker push "moapis/authenticator-admin:${TAG}"
docker push "moapis/authenticator-migrations:${TAG}"