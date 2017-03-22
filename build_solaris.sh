#!/bin/sh
docker run --rm -v $PWD:/go/src/aesgo -v $PWD/target:/go/bin -w /go/src/aesgo craigbarrau/golang-solaris-sparc
