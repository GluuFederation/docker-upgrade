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


def merge_fido2_ctx(ctx):
    with open("/app/templates/v4.2/fido2-dynamic-conf.json") as f:
        dyn_conf = generate_base64_contents(f.read() % ctx)

    with open("/app/templates/v4.2/fido2-static-conf.json") as f:
        static_conf = generate_base64_contents(f.read())

    ctx.update({
        "fido2_dynamic_conf_base64": dyn_conf,
        "fido2_static_conf_base64": static_conf,
    })
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
        ctx = {}
        ctx = merge_extension_ctx(ctx)

        ctx["hostname"] = self.manager.config.get("hostname")
        ctx["fido2ConfigFolder"] = self.manager.config.get("fido2ConfigFolder")
        ctx["oxd_hostname"] = "localhost"
        ctx["oxd_port"] = 8443
        ctx = merge_fido2_ctx(ctx)

        src = "/app/templates/v4.2/extra_entries.ldif"
        dst = "/app/tmp/extra_entries.ldif"
        render_ldif(src, dst, ctx)

        attr_processor = AttrProcessor(
            "/app/static/v4.2/opendj_types.json",
            "/app/static/v4.2/gluu_schema.json",
        )

        parser = LDIFParser(open(dst, "rb"))
        for dn, entry in parser.parse():
            if self.backend_type != "ldap":
                if len(entry) <= 2:
                    continue

                entry["dn"] = [dn]
                entry = transform_entry(entry, attr_processor)
                dn = get_key_from(dn)

            # save to backend
            self.backend.add_entry(dn, entry, **{"bucket": "gluu"})

    def modify_oxauth_config(self):
        key = "ou=oxauth,ou=configuration,o=gluu"
        if self.backend_type != "ldap":
            key = get_key_from(key)

        entry = self.backend.get_entry(key, **{"bucket": "gluu"})
        if not entry:
            return

        hostname = self.manager.config.get("hostname")

        # DYNAMIC CONF

        dynamic_conf = entry.attrs["oxAuthConfDynamic"]
        if self.backend_type == "ldap":
            dynamic_conf = json.loads(dynamic_conf)

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

        # STATIC CONF

        with open("/app/templates/v4.2/oxauth-static-conf.json") as f:
            static_conf = json.loads(f.read())

        # ERRORS CONF

        with open("/app/templates/v4.2/oxauth-errors.json") as f:
            errors_conf = json.loads(f.read())

        if self.backend_type == "ldap":
            dynamic_conf = json.dumps(dynamic_conf)
            static_conf = json.dumps(static_conf)
            errors_conf = json.dumps(errors_conf)

        # increment it to auto-reload related ox apps
        ox_rev = entry.attrs["oxRevision"] + 1

        # save to backend
        self.backend.modify_entry(
            entry.id,
            {
                "oxAuthConfDynamic": dynamic_conf,
                "oxAuthConfStatic": static_conf,
                "oxAuthConfErrors": errors_conf,
                "oxRevision": ox_rev,
            },
            **{"bucket": "gluu"},
        )

    def modify_oxidp_config(self):
        key = "ou=oxidp,ou=configuration,o=gluu"
        if self.backend_type != "ldap":
            key = get_key_from(key)

        entry = self.backend.get_entry(key, **{"bucket": "gluu"})
        if not entry:
            return

        conf = entry.attrs["oxConfApplication"]
        if self.backend_type == "ldap":
            conf = json.loads(conf)

        if "scriptDn" not in conf:
            conf["scriptDn"] = "ou=scripts,o=gluu"

        if self.backend_type == "ldap":
            conf = json.dumps(conf)

        # increment it to auto-reload related ox apps
        ox_rev = entry.attrs["oxRevision"] + 1

        self.backend.modify_entry(
            entry.id,
            {"oxConfApplication": conf, "oxRevision": ox_rev},
            **{"bucket": "gluu"},
        )

    def modify_oxtrust_config(self):
        key = "ou=oxtrust,ou=configuration,o=gluu"
        if self.backend_type != "ldap":
            key = get_key_from(key)

        entry = self.backend.get_entry(key, **{"bucket": "gluu"})
        if not entry:
            return

        hostname = self.manager.config.get("hostname")

        # dynamic

        conf = entry.attrs["oxTrustConfApplication"]
        if self.backend_type == "ldap":
            conf = json.loads(conf)

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
            conf = json.dumps(conf)

        # cache-refresh

        cr_conf = entry.attrs["oxTrustConfCacheRefresh"]
        if self.backend_type == "ldap":
            cr_conf = json.loads(cr_conf)

        if "defaultInumServer" not in conf:
            cr_conf["defaultInumServer"] = True

        if self.backend_type == "ldap":
            cr_conf = json.dumps(cr_conf)

        # increment it to auto-reload related ox apps
        ox_rev = entry.attrs["oxRevision"] + 1

        self.backend.modify_entry(
            entry.id,
            {
                "oxTrustConfApplication": conf,
                "oxTrustConfCacheRefresh": cr_conf,
                "oxRevision": ox_rev,
            },
            **{"bucket": "gluu"},
        )

    def modify_base_config(self):
        key = "ou=configuration,o=gluu"
        if self.backend_type != "ldap":
            key = get_key_from(key)

        entry = self.backend.get_entry(key, **{"bucket": "gluu"})
        if not entry:
            return

        conf = entry.attrs["oxCacheConfiguration"]
        if self.backend_type == "ldap":
            conf = json.loads(conf)

        if "baseDn" not in conf["nativePersistenceConfiguration"]:
            conf["nativePersistenceConfiguration"]["baseDn"] = "o=gluu"

        if self.backend_type == "ldap":
            conf = json.dumps(conf)

        self.backend.modify_entry(
            entry.id,
            {"oxCacheConfiguration": conf},
            **{"bucket": "gluu"},
        )

    def run_upgrade(self):
        logger.info("Updating attributes in persistence.")
        self.modify_attributes()

        logger.info("Updating misc entries in persistence.")
        self.add_new_entries()

        # logger.info("Updating base config in persistence.")
        # self.modify_base_config()

        logger.info("Updating oxAuth config in persistence.")
        self.modify_oxauth_config()

        logger.info("Updating oxIdp config in persistence.")
        self.modify_oxidp_config()

        logger.info("Updating oxTrust config in persistence.")
        self.modify_oxtrust_config()

        # mark as succeed
        return True
