#!/bin/sh

set -e

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /opt/scripts/entrypoint.py
else
    python /opt/scripts/entrypoint.py
fi
