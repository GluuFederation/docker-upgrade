import base64
import json
import itertools
import logging
import os
import random
import string
import time
import uuid

import pyDes
from ldap3 import Connection
from ldap3 import Server
from ldap3 import BASE
from ldap3 import MODIFY_REPLACE

from gluulib import get_manager
from wait_for import wait_for

GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")

manager = get_manager()

logger = logging.getLogger("upgrade")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)

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


def get_ldap_entry(ldap_conn, search_base, search_filter="(objectClass=*)",
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


def modify_oxauth_config(ldap_conn):
    logger.info("Applying updates for oxAuth config (if any).")

    # whether update should be executed
    should_update = False
    fido_folder = manager.config.get("fido2ConfigFolder")
    inumAppliance = manager.config.get("inumAppliance")

    result = get_ldap_entry(
        ldap_conn,
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
    ldap_conn.modify(entry.entry_dn, {
        "oxRevision": [(MODIFY_REPLACE, [ox_rev])],
        "oxAuthConfDynamic": [(MODIFY_REPLACE, [dynamic_conf])],
        "oxAuthConfStatic": [(MODIFY_REPLACE, [static_conf])],
        "oxAuthConfErrors": [(MODIFY_REPLACE, [errors_conf])]
    })

    if ldap_conn.result["description"] == "success":
        logger.info("Updating oxAuth config in secrets backend.")
        manager.secret.set("oxauth_config_base64", generate_base64_contents(dynamic_conf))
        manager.config.set("oxauth_static_conf_base64", generate_base64_contents(static_conf))
        manager.config.set("oxauth_error_base64", generate_base64_contents(errors_conf))


def modify_oxidp_config(ldap_conn):
    logger.info("Applying updates for oxShibboleth config (if any).")

    should_update = False
    hostname = manager.config.get("hostname")
    inumAppliance = manager.config.get("inumAppliance")
    redirect_uri = "https://{}/idp/profile/Logout".format(hostname)

    result = get_ldap_entry(
        ldap_conn,
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
    ldap_conn.modify(entry.entry_dn, {
        "oxRevision": [(MODIFY_REPLACE, [ox_rev])],
        "oxConfApplication": [(MODIFY_REPLACE, [conf])],
    })

    if ldap_conn.result["description"] == "success":
        logger.info("Updating oxShibboleth config in secrets backend.")
        manager.secret.set("oxidp_config_base64", generate_base64_contents(conf))


def modify_clients(ldap_conn):
    logger.info("Applying updates for clients (if any).")

    oxauth_client_id = manager.config.get("oxauth_client_id")
    inumOrg = manager.config.get("inumOrg")
    hostname = manager.config.get("hostname")

    # change oxTrust app
    result = get_ldap_entry(
        ldap_conn,
        "inum={},ou=clients,o={},o=gluu".format(oxauth_client_id, inumOrg),
    )
    if not result:
        logger.warn("Unable to find clients in LDAP.")
        return

    entry = result[0]

    if "oxAuthLogoutURI" in entry.entry_attributes_as_dict:
        return

    logger.info("Updating clients in LDAP.")
    ldap_conn.modify(entry.entry_dn, {
        "oxAuthLogoutURI": [(MODIFY_REPLACE, ["https://{}/identity/logout".format(hostname)])]
    })


def modify_groups(ldap_conn):
    logger.info("Applying updates for groups (if any).")

    inumOrg = manager.config.get("inumOrg")

    # change admin group
    result = get_ldap_entry(
        ldap_conn,
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
        k: [(MODIFY_REPLACE, v)] for k, v in add_attrs.iteritems()
        if k not in entry.entry_attributes_as_dict
    }

    if not new_attrs:
        return

    logger.info("Updating groups in LDAP.")
    ldap_conn.modify(entry.entry_dn, new_attrs)


def add_metric(ldap_conn):
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

    if not get_ldap_entry(ldap_conn, metric["dn"]):
        ldap_conn.add(metric["dn"], attributes=metric["attrs"])
        result = ldap_conn.result

        if result["description"] != "success":
            logger.warn("Unable to add metric; reason={}; "
                        "please try again.".format(result["message"]))
            return

        # if this is the first time metric entry is created,
        # give it delay to allow changes
        time.sleep(5)

    if not get_ldap_entry(ldap_conn, stats["dn"]):
        ldap_conn.add(stats["dn"], attributes=stats["attrs"])
        result = ldap_conn.result

        if result["description"] != "success":
            logger.warn("Unable to add statistic; reason={}; "
                        "please try again.".format(result["message"]))
        return


def modify_oxtrust_config(ldap_conn):
    logger.info("Applying updates for oxTrust config (if any).")

    # whether update should be executed
    should_update = False
    inumAppliance = manager.config.get("inumAppliance")

    result = get_ldap_entry(
        ldap_conn,
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
    ldap_conn.modify(entry.entry_dn, {
        "oxRevision": [(MODIFY_REPLACE, [ox_rev])],
        "oxTrustConfApplication": [(MODIFY_REPLACE, [conf])],
    })

    if ldap_conn.result["description"] == "success":
        logger.info("Updating oxTrust config in secrets backend.")
        manager.secret.set("oxtrust_config_base64", generate_base64_contents(conf))


def main():
    host, port = GLUU_LDAP_URL.split(":", 2)
    user = manager.config.get("ldap_binddn")
    passwd = decrypt_text(manager.secret.get("encoded_ox_ldap_pw"),
                          manager.secret.get("encoded_salt"))

    if not manager.config.get("scim_resource_oxid"):
        manager.config.set("scim_resource_oxid", str(uuid.uuid4()))

    if not manager.config.get("fido2ConfigFolder"):
        manager.config.set("fido2ConfigFolder", "/etc/gluu/conf/fido2")

    with get_ldap_conn(host, port, user, passwd) as conn:
        add_metric(conn)
        modify_clients(conn)
        modify_groups(conn)
        modify_oxauth_config(conn)
        modify_oxidp_config(conn)
        modify_oxtrust_config(conn)


if __name__ == "__main__":
    wait_for(manager, deps=["config", "secret", "ldap"])
    main()
