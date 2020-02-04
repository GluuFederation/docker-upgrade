import logging
import json

from backends import LDAPBackend

logger = logging.getLogger("v41")


class Upgrade41(object):
    def __init__(self, manager):
        self.backend = LDAPBackend(manager)
        self.manager = manager
        self.version = "4.1"

    def modify_oxauth_config(self):
        key = "ou=oxauth,ou=configuration,o=gluu"
        try:
            entry = self.backend.get_entry(key)[0]
        except IndexError:
            return

        should_upgrade = False
        dynamic_conf = json.loads(entry["oxAuthConfDynamic"][0])

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

        logger.info("Updating oxAuth config in persistence.")
        dynamic_conf = json.dumps(dynamic_conf)
        ox_rev = str(int(entry["oxRevision"][0]) + 1)
        self.backend.modify_entry(
            entry.entry_dn,
            {"oxRevision": [ox_rev], "oxAuthConfDynamic": [dynamic_conf]}
        )

    def modify_oxtrust_config(self):
        key = "ou=oxtrust,ou=configuration,o=gluu"
        try:
            entry = self.backend.get_entry(key)[0]
        except IndexError:
            return

        should_upgrade = False
        app_conf = json.loads(entry["oxTrustConfApplication"][0])

        if "useLocalCache" not in app_conf:
            app_conf["useLocalCache"] = True
            should_upgrade = True

        if not should_upgrade:
            return

        logger.info("Updating oxTrust config in persistence.")
        app_conf = json.dumps(app_conf)
        ox_rev = str(int(entry["oxRevision"][0]) + 1)
        self.backend.modify_entry(
            entry.entry_dn,
            {"oxRevision": [ox_rev], "oxTrustConfApplication": [app_conf]}
        )

    def modify_clients(self):
        key = "o=gluu"
        entries = self.backend.all(key, "(objectClass=oxAuthClient)")

        for e in entries:
            if "oxAuthClientSecretExpiresAt" not in e.entry_attributes_as_dict:
                continue

            self.backend.modify_entry(
                e.entry_dn,
                {"oxAuthExpiration": [e.entry_attributes_as_dict["oxAuthClientSecretExpiresAt"]]},
            )

    def run_upgrade(self):
        self.modify_oxauth_config()
        self.modify_oxtrust_config()
        self.modify_clients()
        return True
