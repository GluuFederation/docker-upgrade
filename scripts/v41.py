import json
import logging
import os
from collections import OrderedDict

import ldap3

from persistence import CouchbaseBackend
from persistence import LDAPBackend
from persistence import get_key_from

logger = logging.getLogger("v41")


class Upgrade41:
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
        key = "ou=oxauth,ou=configuration,o=gluu"
        if self.backend_type != "ldap":
            key = get_key_from(key)

        bucket_prefix = os.environ.get("GLUU_COUCHBASE_BUCKET_PREFIX", "gluu")
        entry = self.backend.get_entry(key, **{"bucket": bucket_prefix})

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

        ox_rev = entry.attrs["oxRevision"] + 1

        self.backend.modify_entry(
            entry.id,
            {
                "oxRevision": ox_rev,
                "oxAuthConfDynamic": dynamic_conf,
            },
            **{"bucket": bucket_prefix}
        )

    def modify_oxtrust_config(self):
        key = "ou=oxtrust,ou=configuration,o=gluu"
        if self.backend_type != "ldap":
            key = get_key_from(key)

        bucket_prefix = os.environ.get("GLUU_COUCHBASE_BUCKET_PREFIX", "gluu")
        entry = self.backend.get_entry(key, **{"bucket": bucket_prefix})

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

        ox_rev = entry.attrs["oxRevision"] + 1

        self.backend.modify_entry(
            entry.id,
            {
                "oxRevision": ox_rev,
                "oxTrustConfApplication": app_conf,
            },
            **{"bucket": bucket_prefix}
        )

    def modify_clients(self):
        key = "o=gluu"
        filter_ = "(objectClass=oxAuthClient)"

        if self.backend_type != "ldap":
            key = ""
            filter_ = "objectClass='oxAuthClient'"

        bucket_prefix = os.environ.get("GLUU_COUCHBASE_BUCKET_PREFIX", "gluu")
        entries = self.backend.all(key, filter_, **{"bucket": bucket_prefix})

        for e in entries:
            if "oxAuthClientSecretExpiresAt" not in e.attrs:
                continue

            try:
                self.backend.modify_entry(
                    e.id,
                    {"oxAuthExpiration": e.attrs["oxAuthClientSecretExpiresAt"]},
                    **{"bucket": bucket_prefix}
                )
            except ldap3.core.exceptions.LDAPAttributeError:
                pass

    def update_couchbase_indexes(self):
        bucket_prefix = os.environ.get("GLUU_COUCHBASE_BUCKET_PREFIX", "gluu")

        def get_bucket_mappings(bucket_prefix):
            bucket_mappings = OrderedDict({
                "default": {
                    "bucket": bucket_prefix,
                },
                "user": {
                    "bucket": f"{bucket_prefix}_user",
                },
                "site": {
                    "bucket": f"{bucket_prefix}_site",
                },
                "token": {
                    "bucket": f"{bucket_prefix}_token",
                },
                "cache": {
                    "bucket": f"{bucket_prefix}_cache",
                },
            })

            persistence_type = os.environ.get("GLUU_PERSISTENCE_TYPE", "ldap")
            ldap_mapping = os.environ.get("GLUU_PERSISTENCE_LDAP_MAPPING", "default")

            if persistence_type == "hybrid":
                bucket_mappings = OrderedDict({
                    name: mapping for name, mapping in bucket_mappings.items()
                    if name != ldap_mapping
                })
            return bucket_mappings

        buckets = [mapping["bucket"] for _, mapping in get_bucket_mappings(bucket_prefix).items()]

        with open("/app/templates/v4.1/couchbase_index.json") as f:
            txt = f.read().replace("!bucket_prefix!", bucket_prefix)
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

                    f.write('CREATE INDEX %s ON `%s`(%s) USING GSI WITH {"defer_build":true};\n' % (index_name, bucket, attr_))
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
                        logger.warning("Failed to execute query, reason={}".format(error["msg"]))

    def modify_config(self):
        key = "ou=configuration,o=gluu"
        if self.backend_type != "ldap":
            key = get_key_from(key)

        bucket_prefix = os.environ.get("GLUU_COUCHBASE_BUCKET_PREFIX", "gluu")
        entry = self.backend.get_entry(key, **{"bucket": bucket_prefix})

        if not entry:
            return

        should_upgrade = False

        rm_attrs = (
            "gluuFreeDiskSpace",
            "gluuFreeMemory",
            "gluuFreeSwap",
            "gluuGroupCount",
            "gluuIpAddress",
            "gluuPersonCount",
            "gluuSystemUptime",
        )

        attrs = {
            attr: entry.attrs[attr] for attr in rm_attrs
            if attr in entry.attrs
        }

        if attrs:
            should_upgrade = True

        if not should_upgrade:
            return

        self.backend.modify_entry(
            entry.id,
            attrs,
            **{"bucket": bucket_prefix, "delete_attr": True}
        )

    def add_document_store(self):
        key = "ou=configuration,o=gluu"
        if self.backend_type != "ldap":
            key = get_key_from(key)

        bucket_prefix = os.environ.get("GLUU_COUCHBASE_BUCKET_PREFIX", "gluu")
        entry = self.backend.get_entry(key, **{"bucket": bucket_prefix})

        if not entry:
            return

        if "oxDocumentStoreConfiguration" in entry.attrs:
            return

        doc_config = {
            "documentStoreType": "LOCAL",
            "localConfiguration": {
                "baseLocation": "/",
            },
            "jcaConfiguration": {
                "serverUrl": "http://localhost:8080/rmi",
                "workspaceName": "default",
                "connectionTimeout": 15,
                "userId": "admin",
                "password": "",
            },
            "webDavConfiguration": None,
        }

        if self.backend_type == "ldap":
            doc_config = json.dumps(doc_config)

        modified, err = self.backend.modify_entry(
            entry.id,
            {"oxDocumentStoreConfiguration": doc_config},
            **{"bucket": bucket_prefix}
        )
        if not modified:
            logger.warning("Unable to modify entry; reason={}".format(err))

    def modify_picture_attribute(self):
        key = "inum=EC3A,ou=attributes,o=gluu"
        if self.backend_type != "ldap":
            key = get_key_from(key)

        bucket_prefix = os.environ.get("GLUU_COUCHBASE_BUCKET_PREFIX", "gluu")
        entry = self.backend.get_entry(key, **{"bucket": bucket_prefix})

        if not entry:
            return

        should_upgrade = False

        if entry.attrs["gluuAttributeType"] != "string":
            entry.attrs["gluuAttributeType"] = "string"
            should_upgrade = True

        if not should_upgrade:
            return

        self.backend.modify_entry(
            entry.id,
            {"gluuAttributeType": entry.attrs["gluuAttributeType"]},
            **{"bucket": bucket_prefix}
        )

    def run_upgrade(self):
        logger.info("Updating oxAuth config in persistence.")
        self.modify_oxauth_config()

        logger.info("Updating oxTrust config in persistence.")
        self.modify_oxtrust_config()

        logger.info("Updating clients in persistence.")
        self.modify_clients()

        logger.info("Updating base config in persistence.")
        self.modify_config()
        self.add_document_store()

        if self.backend_type == "couchbase":
            logger.info("Updating Couchbase indexes.")
            self.update_couchbase_indexes()

        logger.info("Updating attributes in persistence.")
        self.modify_picture_attribute()
        return True
