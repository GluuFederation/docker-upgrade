import logging
import json
import os
from collections import OrderedDict

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

        try:
            dynamic_conf = json.loads(entry.attrs["oxAuthConfDynamic"])
        except TypeError:
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
            "deviceAuthzEndpoint": f"https://{hostname}/oxauth/restv1/device_authorization",
            "deviceAuthzRequestExpiresIn": 1800,
            "deviceAuthzTokenPollInterval": 5,
            "deviceAuthzResponseTypeToProcessAuthz": "code",
            "forceOfflineAccessScopeToEnableRefreshToken": False,
        }

        for k, v in new_attrs.items():
            if k not in dynamic_conf:
                dynamic_conf[k] = v

        dynamic_conf["uiLocalesSupported"] = dynamic_conf["uiLocalesSupported"] + ["bg", "de", "fr", "it", "ru", "tr"]
        dynamic_conf["grantTypesSupported"] = dynamic_conf["grantTypesSupported"] + ["urn:ietf:params:oauth:grant-type:device_code"]
        dynamic_conf["dynamicGrantTypeDefault"] = dynamic_conf["dynamicGrantTypeDefault"] + ["urn:ietf:params:oauth:grant-type:device_code"]

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

        try:
            conf = json.loads(entry.attrs["oxConfApplication"])
        except TypeError:
            conf = entry.attrs["oxConfApplication"]

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

        try:
            conf = json.loads(entry.attrs["oxTrustConfApplication"])
        except TypeError:
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
            conf = json.dumps(conf)

        # cache-refresh

        try:
            cr_conf = json.loads(entry.attrs["oxTrustConfCacheRefresh"])
        except TypeError:
            cr_conf = entry.attrs["oxTrustConfCacheRefresh"]

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

        try:
            conf = json.loads(entry.attrs["oxCacheConfiguration"])
        except TypeError:
            conf = entry.attrs["oxCacheConfiguration"]

        if "baseDn" not in conf["nativePersistenceConfiguration"]:
            conf["nativePersistenceConfiguration"]["baseDn"] = "o=gluu"

        if self.backend_type == "ldap":
            conf = json.dumps(conf)

        self.backend.modify_entry(
            entry.id,
            {"oxCacheConfiguration": conf},
            **{"bucket": "gluu"},
        )

    def _modify_couchbase_indexes(self):
        def get_bucket_mappings():
            bucket_mappings = OrderedDict({
                "default": {
                    "bucket": "gluu",
                },
                "user": {
                    "bucket": "gluu_user",
                },
                "site": {
                    "bucket": "gluu_site",
                },
                "token": {
                    "bucket": "gluu_token",
                },
                "cache": {
                    "bucket": "gluu_cache",
                },
                "session": {
                    "bucket": "gluu_session",
                },
            })

            persistence_type = os.environ.get("GLUU_PERSISTENCE_TYPE", "ldap")
            ldap_mapping = os.environ.get("GLUU_PERSISTENCE_LDAP_MAPPING", "default")

            if persistence_type != "couchbase":
                bucket_mappings = OrderedDict({
                    name: mapping for name, mapping in bucket_mappings.items()
                    if name != ldap_mapping
                })
            return bucket_mappings

        buckets = [mapping["bucket"] for _, mapping in get_bucket_mappings().items()]

        with open("/app/templates/v4.2/couchbase_index.json") as f:
            txt = f.read().replace("!bucket_prefix!", "gluu")
            indexes = json.loads(txt)

        for bucket in buckets:
            if bucket not in indexes:
                continue

            query_file = "/app/tmp/index_{}.n1ql".format(bucket)

            with open(query_file, "w") as f:
                index_list = indexes.get(bucket, {})
                index_names = []

                for index in index_list.get("attributes", []):
                    if '(' in ''.join(index):
                        attr_ = index[0]
                        index_name_ = index[0].replace('(', '_').replace(')', '_').replace('`', '').lower()
                        if index_name_.endswith('_'):
                            index_name_ = index_name_[:-1]
                        index_name = 'def_{0}_{1}'.format(bucket, index_name_)
                    else:
                        attr_ = ','.join(['`{}`'.format(a) for a in index])
                        index_name = "def_{0}_{1}".format(bucket, '_'.join(index))

                    f.write('CREATE INDEX %s ON `%s`(%s) USING GSI WITH {"defer_build":false};\n' % (index_name, bucket, attr_))
                    index_names.append(index_name)

                if index_names:
                    f.write('BUILD INDEX ON `%s` (%s) USING GSI;\n' % (bucket, ', '.join(index_names)))

                sic = 1
                for attribs, wherec in index_list.get("static", []):
                    attrquoted = []

                    for a in attribs:
                        if '(' not in a:
                            attrquoted.append('`{}`'.format(a))
                        else:
                            attrquoted.append(a)
                    attrquoteds = ', '.join(attrquoted)

                    f.write('CREATE INDEX `{0}_static_{1:02d}` ON `{0}`({2}) WHERE ({3})\n'.format(bucket, sic, attrquoteds, wherec))
                    sic += 1

            # exec query
            with open(query_file) as f:
                for line in f:
                    query = line.strip()
                    if not query:
                        continue

                    req = self.backend.client.exec_query(query)
                    if not req.ok:
                        # the following code should be ignored
                        # - 4300: index already exists
                        # - 5000: index already built
                        error = req.json()["errors"][0]
                        if error["code"] in (4300, 5000):
                            continue
                        logger.warning(f"Failed to execute query, reason={error['msg']}")

    def _modify_opendj_indexes(self):
        def require_site():
            persistence_type = os.environ.get("GLUU_PERSISTENCE_TYPE", "ldap")
            ldap_mapping = os.environ.get("GLUU_PERSISTENCE_LDAP_MAPPING", "default")

            if persistence_type == "ldap":
                return True
            if persistence_type == "hybrid" and ldap_mapping == "site":
                return True
            return False

        with open("/app/templates/v4.2/opendj_index.json") as f:
            data = json.load(f)

        backends = ["userRoot"]
        if require_site():
            backends.append("site")

        for attr_map in data:
            for backend in attr_map["backend"]:
                if backend not in backends:
                    continue

                dn = f"ds-cfg-attribute={attr_map['attribute']},cn=Index,ds-cfg-backend-id={backend},cn=Backends,cn=config"
                attrs = {
                    'objectClass': ['top', 'ds-cfg-backend-index'],
                    'ds-cfg-attribute': [attr_map['attribute']],
                    'ds-cfg-index-type': attr_map['index'],
                    'ds-cfg-index-entry-limit': ['4000']
                }

                # save to backend
                self.backend.add_entry(dn, attrs, **{"bucket": "gluu"})

    def modify_indexes(self):
        if self.backend_type == "couchbase":
            logger.info("Updating Couchbase indexes.")
            self._modify_couchbase_indexes()
        else:
            logger.info("Updating OpenDJ indexes.")
            self._modify_opendj_indexes()

    def modify_scopes(self):
        scopes = [
            "F0C4",
            "43F1",
            "764C",
            "C17A",
            "D491",
            "341A",
            "10B2",
            "6D99",
            "6D90",
            "7D90",
            "8A01",
            "C4F5",
        ]
        keys = [f"inum={inum},ou=scopes,o=gluu" for inum in scopes]
        if self.backend_type == "couchbase":
            keys = [get_key_from(key) for key in keys]

        ox_attrs = {
            "spontaneousClientId": "",
            "spontaneousClientScopes": [],
            "showInConfigurationEndpoint": True,
        }
        if self.backend_type == "ldap":
            ox_attrs = json.dumps(ox_attrs)

        for id_ in keys:
            self.backend.modify_entry(
                id_,
                {"oxAttributes": ox_attrs},
                **{"bucket": "gluu"}
            )

    def create_session_bucket(self):
        if self.backend_type != "couchbase":
            return

        req = self.backend.client.get_buckets()
        if req.ok:
            remote_buckets = tuple(bckt["name"] for bckt in req.json())
        else:
            remote_buckets = ()

        if "gluu_session" in remote_buckets:
            return

        logger.info("Creating new gluu_session bucket.")

        sys_info = self.backend.client.get_system_info()
        ram_info = sys_info["storageTotals"]["ram"]

        total_mem = (ram_info['quotaTotalPerNode'] - ram_info['quotaUsedPerNode']) / (1024 * 1024)
        min_mem = 100
        memsize = max(int(min_mem), int(total_mem))

        req = self.backend.client.add_bucket("gluu_session", memsize, "couchbase")
        if not req.ok:
            logger.warning(f"Failed to create bucket gluu_session; reason={req.text}")

    def create_shib_user(self):
        if self.backend_type != "couchbase":
            return

        logger.info("Creating Couchbase user for Shibboleth.")
        self.backend.client.create_user(
            'couchbaseShibUser',
            self.manager.secret.get("couchbase_shib_user_password"),
            'Shibboleth IDP',
            'query_select[*]',
        )

    def run_upgrade(self):
        logger.info("Updating attributes in persistence.")
        self.modify_attributes()

        logger.info("Updating misc entries in persistence.")
        self.add_new_entries()

        logger.info("Updating scopes in persistence.")
        self.modify_scopes()

        logger.info("Updating base config in persistence.")
        self.modify_base_config()

        logger.info("Updating oxAuth config in persistence.")
        self.modify_oxauth_config()

        logger.info("Updating oxIdp config in persistence.")
        self.modify_oxidp_config()

        logger.info("Updating oxTrust config in persistence.")
        self.modify_oxtrust_config()

        self.create_session_bucket()

        # modify indexes
        self.modify_indexes()

        self.create_shib_user()

        # mark as succeed
        return True
