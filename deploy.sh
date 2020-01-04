#!/bin/bash

set -e

TAG="$1"
if [ -n "$TRAVIS_TAG" ]; then
    TAG="${TRAVIS_TAG#v}"
fi
export TAG="${TAG}"

docker-compose build
docker-compose push