[![Build Status](https://travis-ci.org/moapis/authenticator.svg?branch=master)](https://travis-ci.org/moapis/authenticator)
[![codecov](https://codecov.io/gh/moapis/authenticator/branch/master/graph/badge.svg)](https://codecov.io/gh/moapis/authenticator)
[![GoDoc](https://godoc.org/github.com/moapis/authenticator?status.svg)](https://godoc.org/github.com/moapis/authenticator)
[![Go Report Card](https://goreportcard.com/badge/github.com/moapis/authenticator)](https://goreportcard.com/report/github.com/moapis/authenticator)

# Authenticator

A stand-alone gRPC based authentication API. Easily integrate authentication into any custom project. Authenticator takes care of user credential storage and checking. It generates JSON Web tokens for users, which easily can be verified by other servers in your ecosystem using performant and secure EdDSA public key cryptography.

### Benefits:

 - Added security, the user credentials live in a seperate database schema as you application's one. Creating a strict seperation in database access;
 - No more password checking logic in you application. Just send a API call to authenticator and check the generated token on each subseqeuent request;

## Fautures

 - gRPC based, simply implement a client in your own preferred language by compiling protobuffer files;
 - Support for master/slave database setups using our own [MultiDB](https://github.com/moapis/multidb) library;
 - Admin panel for user management;
 - A basic HTTP based login server, based on redirects;
 - Argon2 hashed password storage;
 - User *groups* and *"audiences"* for fine grained authorization checking;
 - Comes with the [verify](verify) Go library, which has ready to use token verification methods to integration even easier;

## Status

This project is still under heavy development. We've recently deployed a **beta** version of the gRPC and admin server.

## Future plans

 - Two factor authentication
 - OAuth2 provider support

## Development

When developing against Authenticator, there is a `docker-compose.yml` file which sets up a development infrastructure. It start a postgresql instance, runs the neccesary migrations and start the server instances. You can download the Compose file or run this from the root of the repository:

````
docker compose up
````

- The authenticator gRPC server will be served at port 8765.
- The admin interface will be served at port 1234.

The defaut user is "admin@localhost", password "admin", member of the group "primary" and audience "authenticator".

### Protocol buffers

The authenticator server uses gRPC through protocol buffers generation. To regenerate the gRPC definitions, run:

````
protoc --go_out=plugins=grpc:$(go env GOPATH)/src authenticator.proto
````
