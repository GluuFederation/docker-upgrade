import logging
import json
import os

from ldif3 import LDIFParser

from pygluu.containerlib.utils import (
    generate_base64_contents,
    safe_render,
)

from persistence import (
    CouchbaseBackend,
    LDAPBackend,
    get_key_from,
    AttrProcessor,
    transform_entry,
)

logger = logging.getLogger("v42")


def render_ldif(src, dst, ctx):
    with open(src) as f:
        txt = f.read()

    with open(dst, "w") as f:
        f.write(safe_render(txt, ctx))


def merge_extension_ctx(ctx):
    basedir = "/app/static/v4.2/extension"

    for ext_type in os.listdir(basedir):
        ext_type_dir = os.path.join(basedir, ext_type)

        for fname in os.listdir(ext_type_dir):
            filepath = os.path.join(ext_type_dir, fname)
            ext_name = "{}_{}".format(
                ext_type, os.path.splitext(fname)[0].lower()
            )

            with open(filepath) as fd:
                ctx[ext_name] = generate_base64_contents(fd.read())
    return ctx


class Upgrade42:
    def __init__(self, manager):
        self.manager = manager
        self.version = "4.2"

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

    def modify_attributes(self):
        key = "inum=6049,ou=attributes,o=gluu"

        if self.backend_type != "ldap":
            key = get_key_from(key)

        entry = self.backend.get_entry(key, **{"bucket": "gluu"})

        if entry and "oxAuthClaimName" not in entry.attrs:
            entry.attrs["oxAuthClaimName"] = "user_permission"
            self.backend.modify_entry(entry.id, entry.attrs, **{"bucket": "gluu"})

    def add_new_entries(self):
        ctx = merge_extension_ctx({})
        src = "/app/templates/v4.2/extra_entries.ldif"
        dst = "/app/tmp/extra_entries.ldif"
        render_ldif(src, dst, ctx)

        attr_processor = AttrProcessor(
            "/app/static/v4.2/opendj_types.json",
            "/app/static/v4.2/gluu_schema.json",
        )

        parser = LDIFParser(open(dst, "rb"))
        for dn, entry in parser.parse():
            if self.backend_type == "ldap":
                logger.info(self.backend.add_entry(dn, entry))
            else:
                if len(entry) <= 2:
                    continue
                entry["dn"] = [dn]
                entry = transform_entry(entry, attr_processor)
                dn = get_key_from(dn)
                logger.info(self.backend.add_entry(dn, entry, **{"bucket": "gluu"}))

    def modify_oxauth_config(self):
        key = "ou=oxauth,ou=configuration,o=gluu"
        if self.backend_type != "ldap":
            key = get_key_from(key)

        entry = self.backend.get_entry(key, **{"bucket": "gluu"})
        if not entry:
            return

        hostname = self.manager.config.get("hostname")

        # DYNAMIC CONF

        if self.backend_type == "ldap":
            dynamic_conf = json.loads(entry.attrs["oxAuthConfDynamic"])
        else:
            dynamic_conf = entry.attrs["oxAuthConfDynamic"]

        new_attrs = {
            "backchannelAuthenticationEndpoint": f"https://{hostname}/oxauth/restv1/bc-authorize",
            "backchannelDeviceRegistrationEndpoint": f"https://{hostname}/oxauth/restv1/bc-deviceRegistration",
            "clientRegDefaultToCodeFlowWithRefresh": True,
            "changeSessionIdOnAuthentication": True,
            "returnClientSecretOnRead": True,
            "loggingLayout": "text",
            "backchannelTokenDeliveryModesSupported": [],
            "backchannelAuthenticationRequestSigningAlgValuesSupported": [],
            "backchannelClientId": "",
            "backchannelRedirectUri": "",
            "backchannelUserCodeParameterSupported": False,
            "backchannelBindingMessagePattern": "^[a-zA-Z0-9]{4,8}$",
            "backchannelAuthenticationResponseExpiresIn": 3600,
            "backchannelAuthenticationResponseInterval": 2,
            "backchannelRequestsProcessorJobIntervalSec": 0,
            "backchannelRequestsProcessorJobChunkSize": 100,
            "cibaGrantLifeExtraTimeSec": 180,
            "cibaMaxExpirationTimeAllowedSec": 1800,
            "backchannelLoginHintClaims": ["inum", "uid", "mail"],
            "cibaEndUserNotificationConfig": {
                "apiKey": "",
                "authDomain": "",
                "databaseURL": "",
                "projectId": "",
                "storageBucket": "",
                "messagingSenderId": "",
                "appId": "",
                "notificationUrl": "",
                "notificationKey": "",
                "publicVapidKey": ""
            },
        }

        for k, v in new_attrs.items():
            if k not in dynamic_conf:
                dynamic_conf[k] = v

        dynamic_conf["uiLocalesSupported"] = ["en", "bg", "de", "es", "fr", "it", "ru", "tr"]

        if self.backend_type == "ldap":
            entry.attrs["oxAuthConfDynamic"] = json.dumps(dynamic_conf)
        else:
            entry.attrs["oxAuthConfDynamic"] = dynamic_conf

        # STATIC CONF

        with open("/app/templates/v4.2/oxauth-static-conf.json") as f:
            static_conf = json.loads(f.read())

        if self.backend_type == "ldap":
            entry.attrs["oxAuthConfStatic"] = json.dumps(static_conf)
        else:
            entry.attrs["oxAuthConfStatic"] = static_conf

        # ERRORS CONF

        with open("/app/templates/v4.2/oxauth-errors.json") as f:
            errors_conf = json.loads(f.read())

        if self.backend_type == "ldap":
            entry.attrs["oxAuthConfErrors"] = json.dumps(errors_conf)
        else:
            entry.attrs["oxAuthConfErrors"] = errors_conf
        self.backend.modify_entry(entry.id, entry.attrs, **{"bucket": "gluu"})

    def modify_oxidp_config(self):
        key = "ou=oxidp,ou=configuration,o=gluu"
        if self.backend_type != "ldap":
            key = get_key_from(key)

        entry = self.backend.get_entry(key, **{"bucket": "gluu"})
        if not entry:
            return

        if self.backend_type == "ldap":
            conf = json.loads(entry.attrs["oxConfApplication"])
        else:
            conf = entry.attrs["oxConfApplication"]

        if "scriptDn" not in conf:
            conf["scriptDn"] = "ou=scripts,o=gluu"

        if self.backend_type == "ldap":
            entry.attrs["oxConfApplication"] = json.dumps(conf)
        else:
            entry.attrs["oxConfApplication"] = conf
        # self.backend.modify_entry(entry.id, entry.attrs, **{"bucket": "gluu"})
        logger.info(conf)

    def modify_oxtrust_config(self):
        key = "ou=oxtrust,ou=configuration,o=gluu"
        if self.backend_type != "ldap":
            key = get_key_from(key)

        entry = self.backend.get_entry(key, **{"bucket": "gluu"})
        if not entry:
            return

        hostname = self.manager.config.get("hostname")

        # dynamic

        if self.backend_type == "ldap":
            conf = json.loads(entry.attrs["oxTrustConfApplication"])
        else:
            conf = entry.attrs["oxTrustConfApplication"]

        new_attrs = {
            "loggingLayout": "text",
            "passportUmaClientId": self.manager.config.get("passport_rs_client_id"),
            "passportUmaClientKeyId": self.manager.config.get("passport_rs_client_cert_alias"),
            "passportUmaResourceId": self.manager.config.get("passport_resource_id"),
            "passportUmaScope": f"https://{hostname}/oxauth/restv1/uma/scopes/passport_access",
            "passportUmaClientKeyStoreFile": self.manager.config.get("passport_rs_client_jks_fn"),
            "passportUmaClientKeyStorePassword": self.manager.secret.get("passport_rs_client_jks_pass_encoded"),
        }
        for k, v in new_attrs.items():
            if k not in conf:
                conf[k] = v

        if self.backend_type == "ldap":
            entry.attrs["oxTrustConfApplication"] = json.dumps(conf)
        else:
            entry.attrs["oxTrustConfApplication"] = conf
        self.backend.modify_entry(entry.id, entry.attrs, **{"bucket": "gluu"})

        # @TODO: conf for cache-refresh

    def run_upgrade(self):
        # self.modify_attributes()
        # self.add_new_entries()
        # self.modify_oxauth_config()
        # self.modify_oxidp_config()
        # self.modify_oxtrust_config()
        return False
