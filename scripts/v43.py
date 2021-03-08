import logging
import os

from ldif3 import LDIFParser

from persistence import CouchbaseBackend
from persistence import LDAPBackend
from persistence import get_key_from
from persistence import AttrProcessor
from persistence import transform_entry

from utils import render_ldif
from utils import merge_extension_ctx

logger = logging.getLogger("v43")


class Upgrade43:
    def __init__(self, manager):
        self.manager = manager
        self.version = "4.3"

        persistence_type = os.environ.get("GLUU_PERSISTENCE_TYPE", "ldap")
        ldap_mapping = os.environ.get("GLUU_PERSISTENCE_LDAP_MAPPING", "default")

        if persistence_type == "hybrid":
            if ldap_mapping == "default":
                backend_type = "ldap"
            else:
                backend_type = "couchbase"
        else:
            backend_type = persistence_type

        self.backend_type = backend_type
        if self.backend_type == "ldap":
            self.backend = LDAPBackend(self.manager)
        else:
            self.backend = CouchbaseBackend(self.manager)

    def add_new_entries(self):
        ctx = {}
        ctx = merge_extension_ctx(
            ctx,
            basedir="/app/static/v4.3/extension"
        )

        src = "/app/templates/v4.3/extra_entries.ldif"
        dst = "/app/tmp/extra_entries.ldif"
        render_ldif(src, dst, ctx)

        attr_processor = AttrProcessor(
            "/app/static/v4.2/opendj_types.json",
            "/app/static/v4.2/gluu_schema.json",
        )

        bucket_prefix = os.environ.get("GLUU_COUCHBASE_BUCKET_PREFIX", "gluu")

        with open(dst, "rb") as fd:
            parser = LDIFParser(fd)
            for dn, entry in parser.parse():
                if self.backend_type != "ldap":
                    if len(entry) <= 2:
                        continue

                    entry["dn"] = [dn]
                    entry = transform_entry(entry, attr_processor)
                    dn = get_key_from(dn)

                # save to backend
                self.backend.add_entry(dn, entry, **{"bucket": bucket_prefix})

    def run_upgrade(self):
        logger.info("Updating misc entries in persistence.")
        self.add_new_entries()

        # mark as succeed
        return True
