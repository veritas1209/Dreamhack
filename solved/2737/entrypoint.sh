#!/bin/sh
date +%s%3N > /tmp/genesis_time.txt

exec socat TCP-LISTEN:8000,reuseaddr,fork EXEC:'python3 server.py',stderr