import json
import itertools
import logging
import logging.config
import time
import uuid

from pygluu.containerlib.utils import generate_base64_contents

from backends import LDAPBackend

logger = logging.getLogger("v315")


class Upgrade315(object):
    def __init__(self, manager):
        self.backend = LDAPBackend(manager)
        self.manager = manager
        self.version = "3.1.5"

    def modify_oxauth_config(self):
        logger.info("Applying updates for oxAuth config (if any).")

        # whether update should be executed
        should_update = False
        fido_folder = self.manager.config.get("fido2ConfigFolder")
        inumAppliance = self.manager.config.get("inumAppliance")

        result = self.backend.get_entry(
            "ou=oxauth,ou=configuration,inum={},ou=appliances,o=gluu".format(inumAppliance),
        )
        if not result:
            logger.warn("Unable to find oxAuth config in LDAP.")
            return

        entry = result[0]

        # oxauth-config.json
        dynamic_conf = json.loads(entry["oxAuthConfDynamic"][0])

        # some attributes need to be removed; if any of this attribute is removed
        # determine that update should be executed
        rm_attrs = ["loginPage", "authorizationPage"]
        for attr in rm_attrs:
            if attr not in dynamic_conf:
                continue
            dynamic_conf.pop(attr, None)
            should_update = True

        add_attrs = {
            "loggingLevel": "INFO",
            "errorHandlingMethod": "internal",
            "invalidateSessionCookiesAfterAuthorizationFlow": False,
            "fido2Configuration": {
                "authenticatorCertsFolder": "{}/authenticator_cert".format(fido_folder),
                "mdsCertsFolder": "{}/mds/cert".format(fido_folder),
                "mdsTocsFolder": "{}/mds/toc".format(fido_folder),
                "serverMetadataFolder": "{}/server_metadata".format(fido_folder),
                "userAutoEnrollment": False,
                "unfinishedRequestExpiration": 120,
                "authenticationHistoryExpiration": 1296000,
                "disableFido2": True,
            },
        }
        new_attrs = {k: v for k, v in add_attrs.iteritems() if k not in dynamic_conf}

        if new_attrs:
            dynamic_conf.update(new_attrs)
            should_update = True

        # oxauth-static-conf.json
        static_conf = json.loads(entry["oxAuthConfStatic"][0])
        metric = "ou=statistic,o=metric"
        if static_conf["baseDn"]["metric"] != metric:
            static_conf["baseDn"]["metric"] = metric
            should_update = True

        uma_invalid_scope = "The requested scope is invalid, unknown, malformed, or " \
                            "exceeds the scope granted by the resource owner."

        # oxauth-errors.json
        errors_conf = json.loads(entry.entry_attributes_as_dict["oxAuthConfErrors"][0])

        # change description on UMA invalid_scope
        for error in errors_conf["uma"]:
            if error["id"] != "invalid_scope":
                continue
            if error["description"] != uma_invalid_scope:
                error["description"] = uma_invalid_scope

        # get `invalid_session_found` if any;
        # if it's not found, add new one
        invalid_session_found = list(itertools.ifilter(
            lambda x: x["id"] == "invalid_session_found", errors_conf["authorize"]
        ))

        if not invalid_session_found:
            errors_conf["authorize"].append({
                "id": "invalid_session_found",
                "description": "The authorization server can't handle user authentication due to session expiration",
                "uri": None,
            })
            should_update = True

        # get `invalid_authentication_method` if any;
        # if it's not found, add new one
        invalid_authentication_method = list(itertools.ifilter(
            lambda x: x["id"] == "invalid_authentication_method", errors_conf["authorize"]
        ))
        if not invalid_authentication_method:
            errors_conf["authorize"].append({
                "id": "invalid_authentication_method",
                "description": "The authorization server can't handle user authentication due to error caused by ACR",
                "uri": None,
            })
            should_update = True

        # if there's no update, bail the process
        if not should_update:
            return

        logger.info("Updating oxAuth config in LDAP.")

        dynamic_conf = json.dumps(dynamic_conf)
        static_conf = json.dumps(static_conf)
        errors_conf = json.dumps(errors_conf)
        ox_rev = str(int(entry["oxRevision"][0]) + 1)
        ok, _ = self.backend.modify_entry(
            entry.entry_dn,
            {
                "oxRevision": [ox_rev],
                "oxAuthConfDynamic": [dynamic_conf],
                "oxAuthConfStatic": [static_conf],
                "oxAuthConfErrors": [errors_conf]
            },
        )

        if ok:
            logger.info("Updating oxAuth config in secrets backend.")
            self.manager.secret.set("oxauth_config_base64", generate_base64_contents(dynamic_conf))
            self.manager.config.set("oxauth_static_conf_base64", generate_base64_contents(static_conf))
            self.manager.config.set("oxauth_error_base64", generate_base64_contents(errors_conf))

    def modify_oxidp_config(self):
        logger.info("Applying updates for oxShibboleth config (if any).")

        should_update = False
        hostname = self.manager.config.get("hostname")
        inumAppliance = self.manager.config.get("inumAppliance")
        redirect_uri = "https://{}/idp/profile/Logout".format(hostname)

        result = self.backend.get_entry(
            "ou=oxidp,ou=configuration,inum={},ou=appliances,o=gluu".format(inumAppliance),
        )
        if not result:
            logger.warn("Unable to find oxShibboleth config in LDAP.")
            return

        entry = result[0]

        conf = json.loads(entry["oxConfApplication"][0])

        if conf["openIdPostLogoutRedirectUri"] != redirect_uri:
            conf["openIdPostLogoutRedirectUri"] = redirect_uri
            should_update = True

        if not should_update:
            return

        logger.info("Updating oxShibboleth config in LDAP.")
        conf = json.dumps(conf)
        ox_rev = str(int(entry["oxRevision"][0]) + 1)
        ok, _ = self.backend.modify_entry(
            entry.entry_dn,
            {"oxRevision": [ox_rev], "oxConfApplication": [conf]}
        )

        if ok:
            logger.info("Updating oxShibboleth config in secrets backend.")
            self.manager.secret.set("oxidp_config_base64", generate_base64_contents(conf))

    def modify_clients(self):
        logger.info("Applying updates for clients (if any).")

        oxauth_client_id = self.manager.config.get("oxauth_client_id")
        inumOrg = self.manager.config.get("inumOrg")
        hostname = self.manager.config.get("hostname")

        # change oxTrust app
        result = self.backend.get_entry(
            "inum={},ou=clients,o={},o=gluu".format(oxauth_client_id, inumOrg),
        )
        if not result:
            logger.warn("Unable to find clients in LDAP.")
            return

        entry = result[0]

        if "oxAuthLogoutURI" in entry.entry_attributes_as_dict:
            return

        logger.info("Updating clients in LDAP.")
        self.backend.modify_entry(
            entry.entry_dn,
            {"oxAuthLogoutURI": ["https://{}/identity/logout".format(hostname)]},
        )

    def modify_groups(self):
        logger.info("Applying updates for groups (if any).")

        inumOrg = self.manager.config.get("inumOrg")

        # change admin group
        result = self.backend.get_entry(
            "inum={0}!0003!60B7,ou=groups,o={0},o=gluu".format(inumOrg),
        )
        if not result:
            logger.warn("Unable to find groups in LDAP.")
            return

        entry = result[0]

        add_attrs = {
            "description": ["This group is for administrative purpose, with full acces to users"],
            "gluuGroupVisibility": ["private"],
        }
        new_attrs = {
            k: v for k, v in add_attrs.iteritems()
            if k not in entry.entry_attributes_as_dict
        }

        if not new_attrs:
            return

        logger.info("Updating groups in LDAP.")
        self.backend.modify_entry(entry.entry_dn, new_attrs)

    def add_metric(self):
        logger.info("Applying updates for metric (if any).")

        metric = {
            "dn": "o=metric",
            "attrs": {
                "objectClass": ["top", "organization"],
                "o": ["site"],
            },
        }
        stats = {
            "dn": "ou=statistic,o=metric",
            "attrs": {
                "objectclass": ["top", "organizationalUnit"],
                "ou": ["statistic"],
            }
        }

        if not self.backend.get_entry(metric["dn"]):
            ok, msg = self.backend.add_entry(metric["dn"], metric["attrs"])

            if not ok:
                logger.warn("Unable to add metric; reason={}; "
                            "please try again.".format(msg))
                return

            # if this is the first time metric entry is created,
            # give it delay to allow changes
            time.sleep(5)

        if not self.backend.get_entry(stats["dn"]):
            ok, msg = self.backend.add_entry(stats["dn"], stats["attrs"])

            if not ok:
                logger.warn("Unable to add statistic; reason={}; "
                            "please try again.".format(msg))
            return

    def modify_oxtrust_config(self):
        logger.info("Applying updates for oxTrust config (if any).")

        # whether update should be executed
        should_update = False
        inumAppliance = self.manager.config.get("inumAppliance")

        result = self.backend.get_entry(
            "ou=oxtrust,ou=configuration,inum={},ou=appliances,o=gluu".format(inumAppliance),
        )
        if not result:
            logger.warn("Unable to find oxTrust config in LDAP.")
            return

        entry = result[0]

        # oxtrust-config.json
        conf = json.loads(entry["oxTrustConfApplication"][0])

        rm_attrs = ["velocityLog"]
        for attr in rm_attrs:
            if attr not in conf:
                continue
            conf.pop(attr, None)
            should_update = True

        add_attrs = {
            "loggingLevel": "INFO",
        }
        new_attrs = {k: v for k, v in add_attrs.iteritems() if k not in conf}

        if new_attrs:
            conf.update(new_attrs)
            should_update = True

        # if there's no update, bail the process
        if not should_update:
            return

        logger.info("Updating oxTrust config in LDAP.")

        conf = json.dumps(conf)
        ox_rev = str(int(entry["oxRevision"][0]) + 1)
        ok, _ = self.backend.modify_entry(
            entry.entry_dn,
            {"oxRevision": [ox_rev], "oxTrustConfApplication": [conf]},
        )

        if ok:
            logger.info("Updating oxTrust config in secrets backend.")
            self.manager.secret.set("oxtrust_config_base64",
                                    generate_base64_contents(conf))

    def run_upgrade(self):
        if not self.manager.config.get("scim_resource_oxid"):
            self.manager.config.set("scim_resource_oxid", str(uuid.uuid4()))

        if not self.manager.config.get("fido2ConfigFolder"):
            self.manager.config.set("fido2ConfigFolder", "/etc/gluu/conf/fido2")

        self.add_metric()
        self.modify_clients()
        self.modify_groups()
        self.modify_oxauth_config()
        self.modify_oxidp_config()
        self.modify_oxtrust_config()
        return True
