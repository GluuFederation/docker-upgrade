import argparse
import itertools
import logging
import logging.config
import sys

from pygluu.containerlib import get_manager
from pygluu.containerlib import wait_for

from settings import LOGGING_CONFIG
from v41 import Upgrade41
from v42 import Upgrade42

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("entrypoint")

SUPPORTED_VERSIONS = [
    "4.1",
    "4.2",
]

# current version is the latest supported version
CURRENT_VERSION = SUPPORTED_VERSIONS[-1]

UPGRADER_CLASSES = {
    "4.1": Upgrade41,
    "4.2": Upgrade42,
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

    if args.target < args.source:
        logger.error("Upgrading from {} to {} is not allowed".format(args.source, args.target))
        sys.exit(1)

    if args.source == args.target:
        steps = [args.target]
    else:
        # get all upgrader classes required by the process
        steps = itertools.islice(
            SUPPORTED_VERSIONS,
            SUPPORTED_VERSIONS.index(args.source) + 1,
            SUPPORTED_VERSIONS.index(args.target) + 1,
        )

    upgrader_classes = [UPGRADER_CLASSES.get(step) for step in steps]

    manager = get_manager()
    wait_for(manager, deps=["config", "secret"])

    logger.info(f"Upgrading data from {args.source}")

    for step, upgrader_class in enumerate(upgrader_classes):
        upgrader = upgrader_class(manager)
        logger.info(f"Step {step+1}: upgrading to {upgrader.version}")
        if not upgrader.run_upgrade():
            logger.warning(f"Unable to upgrade version to {upgrader.version}")
            return


if __name__ == "__main__":
    main()
