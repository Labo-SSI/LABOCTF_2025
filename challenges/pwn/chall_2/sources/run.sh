#!/bin/sh

docker build -t pwn_2 ../
docker run --rm -d -p 9696:9696 pwn_2
