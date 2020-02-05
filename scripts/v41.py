import json
import logging
import os

from backends import CouchbaseBackend
from backends import LDAPBackend

logger = logging.getLogger("v41")


class Upgrade41(object):
    def __init__(self, manager):
        self.manager = manager
        self.version = "4.1"

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

    def modify_oxauth_config(self):
        if self.backend_type == "ldap":
            key = "ou=oxauth,ou=configuration,o=gluu"
            kwargs = {}
        else:
            key = "configuration_oxauth"
            kwargs = {"bucket": "gluu"}

        entry = self.backend.get_entry(key, **kwargs)

        if not entry:
            return

        should_upgrade = False

        try:
            dynamic_conf = json.loads(entry.attrs["oxAuthConfDynamic"])
        except TypeError:
            dynamic_conf = entry.attrs["oxAuthConfDynamic"]

        for method in ("tls_client_auth", "self_signed_tls_client_auth"):
            if method in dynamic_conf["tokenEndpointAuthMethodsSupported"]:
                continue
            dynamic_conf["tokenEndpointAuthMethodsSupported"].append(method)
            should_upgrade = True

        if "spontaneousScopeLifetime" not in dynamic_conf:
            dynamic_conf["spontaneousScopeLifetime"] = 86400
            should_upgrade = True

        if "metricReporterEnabled" in dynamic_conf:
            dynamic_conf.pop("metricReporterEnabled", None)
            should_upgrade = True

        if not should_upgrade:
            return

        if self.backend_type == "ldap":
            dynamic_conf = json.dumps(dynamic_conf)
            ox_rev = str(int(entry.attrs["oxRevision"]) + 1)
        else:
            ox_rev = entry.attrs["oxRevision"] + 1

        self.backend.modify_entry(
            entry.id,
            {"oxRevision": ox_rev, "oxAuthConfDynamic": dynamic_conf},
            **kwargs
        )

    def modify_oxtrust_config(self):
        if self.backend_type == "ldap":
            key = "ou=oxtrust,ou=configuration,o=gluu"
            kwargs = {}
        else:
            key = "configuration_oxtrust"
            kwargs = {"bucket": "gluu"}

        entry = self.backend.get_entry(key, **kwargs)

        if not entry:
            return

        should_upgrade = False
        try:
            app_conf = json.loads(entry.attrs["oxTrustConfApplication"])
        except TypeError:
            app_conf = entry.attrs["oxTrustConfApplication"]

        if "useLocalCache" not in app_conf:
            app_conf["useLocalCache"] = True
            should_upgrade = True

        if not should_upgrade:
            return

        if self.backend_type == "ldap":
            app_conf = json.dumps(app_conf)
            ox_rev = str(int(entry.attrs["oxRevision"]) + 1)
        else:
            ox_rev = entry.attrs["oxRevision"] + 1

        self.backend.modify_entry(
            entry.id,
            {"oxRevision": ox_rev, "oxTrustConfApplication": app_conf},
            **kwargs
        )

    def modify_clients(self):
        if self.backend_type == "ldap":
            key = "o=gluu"
            filter_ = "(objectClass=oxAuthClient)"
            kwargs = {}
        else:
            key = ""
            filter_ = "objectClass='oxAuthClient'"
            kwargs = {"bucket": "gluu"}

        entries = self.backend.all(key, filter_, **kwargs)

        for e in entries:
            if "oxAuthClientSecretExpiresAt" not in e.attrs:
                continue

            self.backend.modify_entry(
                e.id,
                {"oxAuthExpiration": e.attrs["oxAuthClientSecretExpiresAt"]},
                **kwargs
            )

    def run_upgrade(self):
        logger.info("Updating oxAuth config in persistence.")
        self.modify_oxauth_config()

        logger.info("Updating oxTrust config in persistence.")
        self.modify_oxtrust_config()

        logger.info("Updating clients in persistence.")
        self.modify_clients()

        return True
