import os

from ldap3 import BASE
from ldap3 import Connection
from ldap3 import MODIFY_REPLACE
from ldap3 import Server
from pygluu.containerlib.utils import decode_text


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

    def get_entry(self, key, filter_="(objectClass=*)", attrs=None):
        attrs = None or ["*"]

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
                {k: [(MODIFY_REPLACE, v)] for k, v in attrs.iteritems()}
            )
            return bool(conn.result["description"] == "success"), conn.result["message"]

    def add_entry(self, key, attrs=None):
        attrs = attrs or {}

        with self.conn as conn:
            conn.add(key, attributes=attrs)
            return bool(conn.result["description"] == "success"), conn.result["message"]


class CouchbaseBackend(object):
    def __init__(self, host, user, password):
        pass

    def get_entry(self):
        pass
