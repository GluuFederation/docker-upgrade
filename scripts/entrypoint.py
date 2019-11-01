import argparse
import itertools
import logging
import logging.config
import sys

from pygluu.containerlib import get_manager
from pygluu.containerlib import wait_for

from settings import LOGGING_CONFIG
from v315 import Upgrade315
from v316 import Upgrade316
from v40 import Upgrade40

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("entrypoint")

SUPPORTED_VERSIONS = [
    "3.1.4",
    "3.1.5",
    "3.1.6",
    "4.0",
]

# current version is the latest supported version
CURRENT_VERSION = SUPPORTED_VERSIONS[-1]

UPGRADER_CLASSES = {
    "3.1.5": Upgrade315,
    "3.1.6": Upgrade316,
    "4.0": Upgrade40,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", help="Source version")
    parser.add_argument("--target", help="Target version")
    args = parser.parse_args()

    if args.source not in SUPPORTED_VERSIONS:
        logger.error("Unsupported source version {}".format(args.source))
        sys.exit(1)

    # backward-compat
    if args.target == "4.0.0":
        args.target = "4.0"

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
    wait_for(manager, deps=["config", "secret"])

    logger.info("Upgrading data")

    prev_version = args.source

    for step, upgrader_class in enumerate(upgrader_classes):
        upgrader = upgrader_class(manager)
        logger.info("Step {}: upgrading {} to {}".format(step + 1, prev_version, upgrader.version))
        if not upgrader.run_upgrade():
            logger.warn("Unable to upgrade version from {} to {}".format(prev_version, upgrader.version))
            return
        prev_version = upgrader.version


if __name__ == "__main__":
    main()
