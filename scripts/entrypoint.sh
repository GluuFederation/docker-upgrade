#!/bin/sh

set -e

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /app/scripts/entrypoint.py "$@"
else
    python /app/scripts/entrypoint.py "$@"
fi
