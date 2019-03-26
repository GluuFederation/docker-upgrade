import argparse
import itertools
import logging
import os
import sys

from gluulib import get_manager
from utils import decrypt_text
from utils import get_ldap_conn
from v315 import ThreeOneFive
from v316 import ThreeOneSix
from wait_for import wait_for

logger = logging.getLogger("upgrade")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)

SUPPORTED_VERSIONS = [
    "3.1.4",
    "3.1.5",
    "3.1.6",
]

# current version is the latest supported version
CURRENT_VERSION = SUPPORTED_VERSIONS[-1]

UPGRADER_CLASSES = {
    "3.1.5": ThreeOneFive,
    "3.1.6": ThreeOneSix,
}


def main():
    GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")

    parser = argparse.ArgumentParser()
    parser.add_argument("--source", help="Source version")
    parser.add_argument("--target", help="Target version")
    args = parser.parse_args()

    if args.source not in SUPPORTED_VERSIONS:
        logger.error("Unsupported source version {}".format(args.source))
        sys.exit(1)

    if args.target not in SUPPORTED_VERSIONS:
        logger.error("Unsupported target version {}".format(args.target))
        sys.exit(1)

    if args.target <= args.source:
        logger.error("Upgrading from {} to {} is not allowed".format(args.source, args.target))
        sys.exit(1)

    # get all upgrader classes required by the process
    steps = itertools.islice(
        SUPPORTED_VERSIONS,
        SUPPORTED_VERSIONS.index(args.source) + 1,
        SUPPORTED_VERSIONS.index(args.target) + 1,
    )
    upgrader_classes = [UPGRADER_CLASSES.get(step) for step in steps]

    manager = get_manager()
    wait_for(manager, deps=["config", "secret", "ldap"])

    host, port = GLUU_LDAP_URL.split(":", 2)
    user = manager.config.get("ldap_binddn")
    passwd = decrypt_text(manager.secret.get("encoded_ox_ldap_pw"),
                          manager.secret.get("encoded_salt"))

    logger.info("Upgrading data")

    with get_ldap_conn(host, port, user, passwd) as conn:
        prev_version = args.source

        for step, upgrader_class in enumerate(upgrader_classes):
            upgrader = upgrader_class(manager, conn)
            logger.info("Step {}: upgrading {} to {}".format(step + 1, prev_version, upgrader.version))
            if not upgrader.run_upgrade():
                logger.warn("Unable to upgrade version from {} to {}".format(prev_version, upgrader.version))
                return
            prev_version = upgrader.version


if __name__ == "__main__":
    main()
