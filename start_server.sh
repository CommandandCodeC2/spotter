#!/bin/bash
# Starts Spotter in the background and writes its output to server.log.
# On first run it creates a Python virtual environment in .venv and installs
# the requirements; if that isn't possible it falls back to the system Python.
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
    echo "First run: setting up the Python environment in .venv ..."
    if ! { python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt; }; then
        echo "Could not set up .venv; using the system Python instead."
        rm -rf .venv
    fi
fi

PYTHON=.venv/bin/python
[ -x "$PYTHON" ] || PYTHON=python3

exec "$PYTHON" server.py >> server.log 2>&1 &
