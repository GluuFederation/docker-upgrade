# import itertools
import logging
# import json
# import os

from ldif3 import LDIFParser

from backends import LDAPBackend
from modifiers import SiteModifier
from modifiers import MetricModifier
from modifiers import GluuModifier

logger = logging.getLogger("v400")


class Upgrade400(object):
    def __init__(self, manager):
        self.backend = LDAPBackend(manager)
        self.manager = manager
        self.version = "4.0.0"

    def modify_site(self):
        file_ = "/app/imports/site.ldif"

        try:
            logger.info("Processing upgrade for o=site backend")
            parser = LDIFParser(open(file_))
            mod = SiteModifier(self.manager)

            for dn, entry in parser.parse():
                dn, entry = mod.process(dn, entry)
                if not dn:
                    continue

                modified, err = self.backend.upsert_entry(dn, entry)
                if not modified:
                    logger.warn(err)
        except IOError as exc:
            logger.warning("Unable to process upgrade for o=site backend; "
                           "reason={}".format(exc))

    def modify_metric(self):
        file_ = "/app/imports/metric.ldif"

        try:
            logger.info("Processing upgrade for o=metric backend")
            parser = LDIFParser(open(file_))
            mod = MetricModifier(self.manager)

            for dn, entry in parser.parse():
                dn, entry = mod.process(dn, entry)
                if not dn:
                    continue

                modified, err = self.backend.upsert_entry(dn, entry)
                if not modified:
                    logger.warn(err)
        except IOError as exc:
            logger.warning("Unable to process upgrade for o=metric backend; "
                           "reason={}".format(exc))

    def modify_user_root(self):
        file_ = "/app/imports/gluu.ldif"

        try:
            logger.info("Processing upgrade for o=gluu backend")
            parser = LDIFParser(open(file_))
            mod = GluuModifier(self.manager)

            for dn, entry in parser.parse():
                dn, entry = mod.process(dn, entry)
                if not dn:
                    continue

                # modified, err = self.backend.upsert_entry(dn, entry)
                # if not modified:
                #     logger.warn(err)

            # # the following entries are needed by Gluu Server v4
            # self.add_base_entries()
        except IOError as exc:
            logger.warning("Unable to process upgrade for o=gluu backend; "
                           "reason={}".format(exc))

    def add_base_entries(self):
        data = [
            {
                "dn": "ou=pct,ou=uma,o=gluu",
                "attrs": {
                    "objectClass": ["top", "organizationalUnit"],
                    "ou": ["pct"],
                },
            },
            {
                "dn": "ou=resetPasswordRequests,o=gluu",
                "attrs": {
                    "objectClass": ["top", "organizationalUnit"],
                    "ou": ["resetPasswordRequests"],
                },
            },

            {
                "dn": "ou=tokens,o=gluu",
                "attrs": {
                    "objectClass": ["top", "organizationalUnit"],
                    "ou": ["tokens"],
                },
            },
            {
                "dn": "ou=authorizations,o=gluu",
                "attrs": {
                    "objectClass": ["top", "organizationalUnit"],
                    "ou": ["authorizations"],
                },
            },
            {
                "dn": "ou=samlAcrs,o=gluu",
                "attrs": {
                    "objectClass": ["top", "organizationalunit"],
                    "ou": ["samlAcrs"],
                },
            },
            {
                "dn": "ou=metric,o=gluu",
                "attrs": {
                    "objectClass": ["top", "organizationalunit"],
                    "ou": ["metric"],
                },
            },
        ]

        for datum in data:
            entry = self.backend.get_entry(datum["dn"])
            if entry:
                continue

            _, err = self.backend.add_entry(datum["dn"], datum["attrs"])
            if err:
                logger.warn(err)

    def run_upgrade(self):
        # self.modify_site()
        # self.modify_metric()
        self.modify_user_root()
