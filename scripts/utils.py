import base64
import random
import string
import uuid

import pyDes
from ldap3 import BASE
from ldap3 import Connection
from ldap3 import Server


# Default charset
_DEFAULT_CHARS = "".join([string.ascii_uppercase,
                          string.digits,
                          string.lowercase])


def get_ldap_conn(host, port, user, passwd):
    server = Server(host, int(port), use_ssl=True)
    return Connection(server, user, passwd)


def reindent(text, num_spaces=1):
    text = [(num_spaces * " ") + line.lstrip() for line in text.splitlines()]
    text = "\n".join(text)
    return text


def generate_base64_contents(text, num_spaces=1):
    text = text.encode("base64").strip()
    if num_spaces > 0:
        text = reindent(text, num_spaces)
    return text


def decrypt_text(encrypted_text, key):
    cipher = pyDes.triple_des(b"{}".format(key), pyDes.ECB,
                              padmode=pyDes.PAD_PKCS5)
    encrypted_text = b"{}".format(base64.b64decode(encrypted_text))
    return cipher.decrypt(encrypted_text)


def encrypt_text(text, key):
    cipher = pyDes.triple_des(b"{}".format(key), pyDes.ECB,
                              padmode=pyDes.PAD_PKCS5)
    encrypted_text = cipher.encrypt(b"{}".format(text))
    return base64.b64encode(encrypted_text)


def get_random_chars(size=12, chars=_DEFAULT_CHARS):
    """Generates random characters.
    """
    return ''.join(random.choice(chars) for _ in range(size))


def join_quad_str(x):
    return ".".join([get_quad() for _ in xrange(x)])


def get_quad():
    # borrowed from community-edition-setup project
    # see http://git.io/he1p
    return str(uuid.uuid4())[:4].upper()


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
