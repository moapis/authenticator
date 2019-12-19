# protoc

Regenerate the grpc code, from the project root, with:

````
protoc --go_out=plugins=grpc:. ./pb/authenticator.proto 
````