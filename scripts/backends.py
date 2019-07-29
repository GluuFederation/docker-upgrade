import os

from ldap3 import BASE
from ldap3 import Connection
from ldap3 import Server
# from pygluu.containerlib.utils import decode_text


class LDAPBackend(object):
    def __init__(self, manager):
        url = os.environ.get("GLUU_LDAP_URL", "localhost:1636")
        # user = manager.config.get("ldap_binddn")
        # passwd = decode_text(
        #     manager.secret.get("encoded_ox_ldap_pw"),
        #     manager.secret.get("encoded_salt"),
        # )

        self.server = Server(url, port=1636, use_ssl=True)
        self.manager = manager


class CouchbaseBackend(object):
    def __init__(self, host, user, password):
        pass


def get_ldap_conn(host, port, user, passwd):
    server = Server(host, int(port), use_ssl=True)
    return Connection(server, user, passwd)


def get_ldap_entry(ldap_conn, search_base,
                   search_filter="(objectClass=*)",
                   search_scope=BASE, attrs=None):
    attrs = None or ["*"]
    ldap_conn.search(
        search_base=search_base,
        search_filter=search_filter,
        search_scope=search_scope,
        attributes=attrs,
    )

    if not ldap_conn.entries:
        return []
    return ldap_conn.entries
