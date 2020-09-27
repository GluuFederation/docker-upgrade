import contextlib
import json
import os
from collections import namedtuple

from ldap3 import BASE
from ldap3 import Connection
from ldap3 import MODIFY_DELETE
from ldap3 import MODIFY_REPLACE
from ldap3 import Server
from ldap3 import SUBTREE
from ldap3.utils.dn import safe_dn
from ldap3.utils.dn import to_dn

from pygluu.containerlib.utils import decode_text
from pygluu.containerlib.persistence.couchbase import CouchbaseClient
from pygluu.containerlib.persistence.couchbase import get_couchbase_password
from pygluu.containerlib.persistence.couchbase import get_couchbase_user
from pygluu.containerlib.persistence.couchbase import get_couchbase_superuser_password
from pygluu.containerlib.persistence.couchbase import get_couchbase_superuser


class LegacyLDAPBackend(object):
    def __init__(self, manager):
        url = os.environ.get("GLUU_LDAP_URL", "localhost:1636")
        user = manager.config.get("ldap_binddn")
        passwd = decode_text(
            manager.secret.get("encoded_ox_ldap_pw"),
            manager.secret.get("encoded_salt"),
        )

        server = Server(url, port=1636, use_ssl=True)
        self.conn = Connection(server, user, passwd)
        self.manager = manager

    def get_entry(self, key, filter_="", attrs=None):
        attrs = None or ["*"]
        filter_ = filter_ or "(objectClass=*)"

        with self.conn as conn:
            conn.search(
                search_base=key,
                search_filter=filter_,
                search_scope=BASE,
                attributes=attrs,
            )

            if not conn.entries:
                return []
            return conn.entries

    def modify_entry(self, key, attrs=None):
        attrs = attrs or {}

        with self.conn as conn:
            conn.modify(
                key,
                {k: [(MODIFY_REPLACE, v)] for k, v in attrs.items()}
            )
            return bool(conn.result["description"] == "success"), conn.result["message"]

    def add_entry(self, key, attrs=None):
        attrs = attrs or {}

        with self.conn as conn:
            conn.add(key, attributes=attrs)
            return bool(conn.result["description"] == "success"), conn.result["message"]

    def delete_entry(self, key):
        with self.conn as conn:
            conn.delete(key)
            return bool(conn.result["description"] == "success"), conn.result["message"]

    def upsert_entry(self, key, attrs=None):
        attrs = attrs or {}

        saved, err = self.modify_entry(key, attrs)
        if not saved:
            saved, err = self.add_entry(key, attrs)
        return saved, err

    def all(self, key="", filter_="", attrs=None):
        key = key or "o=gluu"
        attrs = None or ["*"]
        filter_ = filter_ or "(objectClass=*)"

        with self.conn as conn:
            conn.search(
                search_base=key,
                search_filter=filter_,
                search_scope=SUBTREE,
                attributes=attrs,
            )
            for e in conn.entries:
                yield e


#: shortcut to ldap3.utils.dn:to_dn
explode_dn = to_dn

#: shortcut to ldap3.utils.dn:safe_dn
implode_dn = safe_dn

Entry = namedtuple("Entry", ["id", "attrs"])


class LDAPBackend(object):
    def __init__(self, manager):
        url = os.environ.get("GLUU_LDAP_URL", "localhost:1636")
        user = manager.config.get("ldap_binddn")
        passwd = decode_text(
            manager.secret.get("encoded_ox_ldap_pw"),
            manager.secret.get("encoded_salt"),
        )

        server = Server(url, port=1636, use_ssl=True)
        self.conn = Connection(server, user, passwd)
        self.manager = manager

    def get_entry(self, key, filter_="", attrs=None, **kwargs):
        attrs = None or ["*"]
        filter_ = filter_ or "(objectClass=*)"

        with self.conn as conn:
            conn.search(
                search_base=key,
                search_filter=filter_,
                search_scope=BASE,
                attributes=attrs,
            )

            if not conn.entries:
                return

            entry = conn.entries[0]
            id_ = entry.entry_dn
            attrs = {}

            for k, v in entry.entry_attributes_as_dict.items():
                # if len(v) < 2:
                #     v = v[0]
                attrs[k] = v
            return Entry(id_, attrs)

    def modify_entry(self, key, attrs=None, **kwargs):
        attrs = attrs or {}
        del_flag = kwargs.get("delete_attr", False)

        if del_flag:
            mod = MODIFY_DELETE
        else:
            mod = MODIFY_REPLACE

        for k, v in attrs.items():
            if not isinstance(v, list):
                v = [v]
            attrs[k] = [(mod, v)]

        with self.conn as conn:
            conn.modify(key, attrs)
            return bool(conn.result["description"] == "success"), conn.result["message"]

    def add_entry(self, key, attrs=None, **kwargs):
        attrs = attrs or {}

        for k, v in attrs.items():
            if not isinstance(v, list):
                v = [v]
            attrs[k] = v

        with self.conn as conn:
            conn.add(key, attributes=attrs)
            return bool(conn.result["description"] == "success"), conn.result["message"]

    def delete_entry(self, key, **kwargs):
        with self.conn as conn:
            conn.delete(key)
            return bool(conn.result["description"] == "success"), conn.result["message"]

    def upsert_entry(self, key, attrs=None, **kwargs):
        attrs = attrs or {}

        saved, err = self.modify_entry(key, attrs)
        if not saved:
            saved, err = self.add_entry(key, attrs)
        return saved, err

    def all(self, key="", filter_="", attrs=None, **kwargs):
        key = key or "o=gluu"

        attrs = None or ["*"]
        filter_ = filter_ or "(objectClass=*)"

        with self.conn as conn:
            conn.search(
                search_base=key,
                search_filter=filter_,
                search_scope=SUBTREE,
                attributes=attrs,
            )

            for entry in conn.entries:
                id_ = entry.entry_dn
                attrs = entry.entry_attributes_as_dict

                for k, v in attrs.items():
                    # if len(v) < 2:
                    #     v = v[0]
                    attrs[k] = v
                yield Entry(id_, attrs)


class CouchbaseBackend(object):
    def __init__(self, manager):
        hosts = os.environ.get("GLUU_COUCHBASE_URL", "localhost")
        user = get_couchbase_superuser(manager) or get_couchbase_user(manager)

        password = ""
        with contextlib.suppress(FileNotFoundError):
            password = get_couchbase_superuser_password(manager)
        password = password or get_couchbase_password(manager)

        # hosts = os.environ.get("GLUU_COUCHBASE_URL", "localhost")
        # user = get_couchbase_user(manager)
        # password = get_couchbase_password(manager)
        self.client = CouchbaseClient(hosts, user, password)

    def get_entry(self, key, filter_="", attrs=None, **kwargs):
        bucket = kwargs.get("bucket")
        req = self.client.exec_query(
            "SELECT META().id, {0}.* FROM {0} USE KEYS '{1}'".format(bucket, key)
        )
        if req.ok:
            attrs = req.json()["results"][0]
            return Entry(attrs.pop("id"), attrs)
        return

    def modify_entry(self, key, attrs=None, **kwargs):
        bucket = kwargs.get("bucket")
        del_flag = kwargs.get("delete_attr", False)

        if del_flag:
            mod_kv = "UNSET {}".format(
                ",".join([k for k, _ in attrs.items()])
            )
        else:
            mod_kv = "SET {}".format(
                ",".join(["{}={}".format(k, json.dumps(v)) for k, v in attrs.items()])
            )

        query = "UPDATE {} USE KEYS '{}' {}".format(bucket, key, mod_kv)
        req = self.client.exec_query(query)
        if req.ok:
            resp = req.json()
            return resp["status"] == "success", resp["status"]
        return False, ""

    # def add_entry(self, key, attrs=None, **kwargs):
    #     bucket = kwargs.get("bucket")

    # def upsert_entry(self, key, attrs=None, **kwargs):
    #     bucket = kwargs.get("bucket")

    def all(self, key="", filter_="", attrs=None, **kwargs):
        bucket = kwargs.get("bucket")

        req = self.client.exec_query(
            "SELECT META().id, {0}.* FROM {0} WHERE {1}".format(bucket, filter_)
        )
        if req.ok:
            for entry in req.json()["results"]:
                yield Entry(entry.pop("id"), entry)
