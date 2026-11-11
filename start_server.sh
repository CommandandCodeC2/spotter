#!/bin/bash
cd "$(dirname "$0")"
exec python3 server.py >> server.log 2>&1 &
