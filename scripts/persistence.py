import datetime
import json
import os
from collections import namedtuple

from ldap3 import BASE
from ldap3 import Connection
from ldap3 import MODIFY_DELETE
from ldap3 import MODIFY_REPLACE
from ldap3 import Server
# from ldap3 import SUBTREE
# from ldap3.utils.dn import safe_dn
# from ldap3.utils.dn import to_dn

from pygluu.containerlib.utils import decode_text
from pygluu.containerlib.persistence.couchbase import CouchbaseClient as _CBClient
from pygluu.containerlib.persistence.couchbase import get_couchbase_password
from pygluu.containerlib.persistence.couchbase import get_couchbase_user

Entry = namedtuple("Entry", ["id", "attrs"])


class AttrProcessor:
    def __init__(self, opendj_types_fn, gluu_schema_fn):
        self._attrs = {}
        self.opendj_types_fn = opendj_types_fn
        self.gluu_schema_fn = gluu_schema_fn

    @property
    def syntax_types(self):
        return {
            "1.3.6.1.4.1.1466.115.121.1.7": "boolean",
            "1.3.6.1.4.1.1466.115.121.1.27": "integer",
            "1.3.6.1.4.1.1466.115.121.1.24": "datetime",
        }

    def process(self):
        attrs = {}

        # with open("/app/static/opendj_types.json") as f:
        with open(self.opendj_types_fn) as f:
            attr_maps = json.loads(f.read())
            for type_, names in attr_maps.items():
                for name in names:
                    attrs[name] = {"type": type_, "multivalued": False}

        # with open("/app/static/gluu_schema.json") as f:
        with open(self.gluu_schema_fn) as f:
            gluu_schema = json.loads(f.read()).get("attributeTypes", {})
            for schema in gluu_schema:
                if schema.get("json"):
                    type_ = "json"
                elif schema["syntax"] in self.syntax_types:
                    type_ = self.syntax_types[schema["syntax"]]
                else:
                    type_ = "string"

                multivalued = schema.get("multivalued", False)
                for name in schema["names"]:
                    attrs[name] = {
                        "type": type_,
                        "multivalued": multivalued,
                    }

        # override `member`
        attrs["member"]["multivalued"] = True
        return attrs

    @property
    def attrs(self):
        if not self._attrs:
            self._attrs = self.process()
        return self._attrs

    def is_multivalued(self, name):
        return self.attrs.get(name, {}).get("multivalued", False)

    def get_type(self, name):
        return self.attrs.get(name, {}).get("type", "string")


def transform_values(name, values, attr_processor):
    def as_dict(val):
        return json.loads(val)

    def as_bool(val):
        return val.lower() in ("true", "yes", "1", "on")

    def as_int(val):
        try:
            val = int(val)
        except (TypeError, ValueError):
            pass
        return val

    def as_datetime(val):
        if "." in val:
            date_format = "%Y%m%d%H%M%S.%fZ"
        else:
            date_format = "%Y%m%d%H%M%SZ"

        if not val.lower().endswith("z"):
            val += "Z"

        dt = datetime.datetime.strptime(val, date_format)
        return dt.isoformat()

    callbacks = {
        "json": as_dict,
        "boolean": as_bool,
        "integer": as_int,
        "datetime": as_datetime,
    }

    type_ = attr_processor.get_type(name)
    callback = callbacks.get(type_)

    # maybe string
    if not callable(callback):
        return values
    return [callback(item) for item in values]


def transform_entry(entry, attr_processor):
    for k, v in entry.items():
        v = transform_values(k, v, attr_processor)

        if len(v) == 1 and attr_processor.is_multivalued(k) is False:
            entry[k] = v[0]

        if k != "objectClass":
            continue

        entry[k].remove("top")
        ocs = entry[k]

        for oc in ocs:
            remove_oc = any(["Custom" in oc, "gluu" not in oc.lower()])
            if len(ocs) > 1 and remove_oc:
                ocs.remove(oc)
        entry[k] = ocs[0]
    return entry


def get_key_from(dn):
    # for example: `"inum=29DA,ou=attributes,o=gluu"`
    # becomes `["29DA", "attributes"]`
    dns = [i.split("=")[-1] for i in dn.split(",") if i != "o=gluu"]
    dns.reverse()

    # the actual key
    return "_".join(dns) or "_"


class LDAPBackend:
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
        def format_attrs(attrs):
            _attrs = {}
            for k, v in attrs.items():
                if len(v) < 2:
                    v = v[0]
                _attrs[k] = v
            return _attrs

        attrs = None or ["*"]
        filter_ = filter_ or "(objectClass=*)"

        with self.conn as conn:
            conn.search(
                search_base=key,
                search_filter=filter_,
                search_scope=BASE,
                attributes=attrs,
                size_limit=1,
            )

            if not conn.entries:
                return

            entry = conn.entries[0]
            return Entry(entry.entry_dn, format_attrs(entry.entry_attributes_as_dict))

    def add_entry(self, key, attrs=None, **kwargs):
        attrs = attrs or {}

        with self.conn as conn:
            conn.add(key, attributes=attrs)
            return bool(conn.result["description"] == "success"), conn.result["message"]

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


class CouchbaseBackend:
    def __init__(self, manager):
        hosts = os.environ.get("GLUU_COUCHBASE_URL", "localhost")
        user = get_couchbase_user(manager)
        password = get_couchbase_password(manager)
        self.client = _CBClient(hosts, user, password)

    def get_entry(self, key, filter_="", attrs=None, **kwargs):
        bucket = kwargs.get("bucket")
        req = self.client.exec_query(
            f"SELECT META().id, {bucket}.* FROM {bucket} USE KEYS '{key}'"
        )
        if not req.ok:
            return

        attrs = req.json()["results"][0]
        id_ = attrs.pop("id")
        return Entry(id_, attrs)

    def add_entry(self, key, attrs=None, **kwargs):
        bucket = kwargs.get("bucket")
        attrs = json.dumps(attrs)
        query = 'INSERT INTO `%s` (KEY, VALUE) VALUES ("%s", %s)' % (bucket, key, attrs)

        req = self.client.exec_query(query)

        if req.ok:
            resp = req.json()
            status = bool(resp["status"] == "success")
            message = resp["status"]
        else:
            status = False
            message = req.text or req.reason
        return status, message

    def modify_entry(self, key, attrs=None, **kwargs):
        bucket = kwargs.get("bucket")
        del_flag = kwargs.get("delete_attr", False)

        if del_flag:
            kv = ",".join(attrs.keys())
            mod_kv = f"UNSET {kv}"
        else:
            kv = ",".join([
                "{}={}".format(k, json.dumps(v))
                for k, v in attrs.items()
            ])
            mod_kv = f"SET {kv}"

        query = f"UPDATE {bucket} USE KEYS '{key}' {mod_kv}"
        req = self.client.exec_query(query)

        if req.ok:
            resp = req.json()
            status = bool(resp["status"] == "success")
            message = resp["status"]
        else:
            status = False
            message = req.text or req.reason
        return status, message
