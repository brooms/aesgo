#!/bin/sh
docker run --rm -v $PWD:/go/src/aesgo -v $PWD/target:/go/bin -w /go/src/aesgo -e GOOS=windows -e GOARCH=386 golang:1.8 go build -v -o /go/bin/aesgo.exe