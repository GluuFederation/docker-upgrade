import logging
import logging.config

from backends import LDAPBackend

logger = logging.getLogger("v400")


class Upgrade400(object):
    def __init__(self, manager):
        self.backend = LDAPBackend(manager)
        self.manager = manager
        self.version = "4.0.0"

    def dump_entries(self):
        keys = [
            "o=gluu",
            "o=site",
            "o=metric",
        ]

        for key in keys:
            total = 0
            for x in self.backend.all(key):
                logger.info("DN: {}".format(x["dn"]))
                total += 1
            logger.info("Total entries for {}: {}".format(key, total))

    def run_upgrade(self):
        self.dump_entries()
