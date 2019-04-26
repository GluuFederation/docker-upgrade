#!/bin/sh

set -e

cat << LICENSE_ACK

# ========================================================================================= #
# Gluu License Agreement: https://github.com/GluuFederation/gluu-docker/blob/3.1.6/LICENSE. #
# The use of Gluu Server Docker Edition is subject to the Gluu Support License.             #
# ========================================================================================= #

LICENSE_ACK

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /opt/scripts/entrypoint.py "$@"
else
    python /opt/scripts/entrypoint.py "$@"
fi
