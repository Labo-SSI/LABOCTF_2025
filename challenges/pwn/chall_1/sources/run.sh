#!/bin/sh

docker build -t pwn_1 ../
docker run --rm -d -p 6969:6969 pwn_1
