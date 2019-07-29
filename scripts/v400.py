import logging
import logging.config

from settings import LOGGING_CONFIG

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("upgrade_4.0.0")


class Upgrade400(object):
    def __init__(self, manager):
        self.backend = None
        self.manager = manager

    def run_upgrade(self):
        logger.info("Nothing to run")
