#!/bin/sh

set -e

cat << LICENSE_ACK

# ================================================================================================ #
# Gluu License Agreement: https://github.com/GluuFederation/enterprise-edition/blob/4.0.0/LICENSE. #
# The use of Gluu Server Docker Edition is subject to the Gluu Support License.                    #
# ================================================================================================ #

LICENSE_ACK

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /app/scripts/entrypoint.py "$@"
else
    python /app/scripts/entrypoint.py "$@"
fi
