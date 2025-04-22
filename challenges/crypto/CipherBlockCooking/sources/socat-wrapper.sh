#!/bin/bash

socat TCP-LISTEN:1234,reuseaddr,fork EXEC:"python3 server.py",pty,stderr
