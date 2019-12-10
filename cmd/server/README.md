# Server development

## Migrations

From project root, run migrations for development on a local database `authenticator` with:

````
cd migrations
sql-migrate up
````

## Models

From project root, regenerate models with:

````
sqlboiler --wipe --config config/sqlboiler.yml psql
````

## Local server

Build and start a local server on a local database `authenticator` with:

````
go build && ./server -config config/development.json
````

