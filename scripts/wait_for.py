import argparse
import base64
import logging
import os
import re
import sys
import time

import ldap3
import pyDes

from gluulib import get_manager

logger = logging.getLogger("wait_for")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)


def wait_for_config(manager, max_wait_time, sleep_duration):
    for i in range(0, max_wait_time, sleep_duration):
        try:
            reason = "config 'hostname' is not available"
            if manager.config.get("hostname"):
                logger.info("Config backend is ready.")
                return
        except Exception as exc:
            reason = exc

        logger.warn("Config backend is not ready; reason={}; "
                    "retrying in {} seconds.".format(reason, sleep_duration))
        time.sleep(sleep_duration)

    logger.error("Config backend is not ready after {} seconds.".format(max_wait_time))
    sys.exit(1)


def wait_for_secret(manager, max_wait_time, sleep_duration):
    for i in range(0, max_wait_time, sleep_duration):
        try:
            reason = "secret 'ssl_cert' is not available"
            if manager.secret.get("ssl_cert"):
                logger.info("Secret backend is ready.")
                return
        except Exception as exc:
            reason = exc

        logger.warn("Secret backend is not ready; reason={}; "
                    "retrying in {} seconds.".format(reason, sleep_duration))
        time.sleep(sleep_duration)

    logger.error("Secret backend is not ready after {} seconds.".format(max_wait_time))
    sys.exit(1)


def get_ldap_password(manager):
    encoded_password = ""
    encoded_salt = ""

    try:
        with open("/etc/gluu/conf/ox-ldap.properties") as f:
            txt = f.read()
            result = re.findall("bindPassword: (.+)", txt)
            if result:
                encoded_password = result[0]
    except IOError:
        encoded_password = manager.secret.get("encoded_ox_ldap_pw")

    try:
        with open("/etc/gluu/conf/salt") as f:
            txt = f.read()
            encoded_salt = txt.split("=")[-1].strip()
    except IOError:
        encoded_salt = manager.secret.get("encoded_salt")

    cipher = pyDes.triple_des(
        b"{}".format(encoded_salt),
        pyDes.ECB,
        padmode=pyDes.PAD_PKCS5
    )
    encrypted_text = b"{}".format(base64.b64decode(encoded_password))
    return cipher.decrypt(encrypted_text)


def wait_for_ldap(manager, max_wait_time, sleep_duration):
    GLUU_LDAP_URL = os.environ.get("GLUU_LDAP_URL", "localhost:1636")

    ldap_bind_dn = manager.config.get("ldap_binddn")
    ldap_password = get_ldap_password(manager)

    ldap_host = GLUU_LDAP_URL.split(":")[0]
    ldap_port = int(GLUU_LDAP_URL.split(":")[1])

    ldap_server = ldap3.Server(
        ldap_host,
        ldap_port,
        use_ssl=True
    )
    logger.info(
        "LDAP trying ldaps://" + str(GLUU_LDAP_URL) +
        " ldap_bind_dn=" + ldap_bind_dn
    )

    # check the entries few times, to ensure OpenDJ is running after importing
    # initial data; this may not required for OpenLDAP
    successive_entries_check = 0

    for i in range(0, max_wait_time, sleep_duration):
        try:
            with ldap3.Connection(
                    ldap_server,
                    ldap_bind_dn,
                    ldap_password) as ldap_connection:

                ldap_connection.search(
                    search_base="o=gluu",
                    search_filter="(oxScopeType=openid)",
                    search_scope=ldap3.SUBTREE,
                    attributes=['*']
                )

                if successive_entries_check >= 3:
                    logger.info("LDAP is up and populated :-)")
                    return 0

                if ldap_connection.entries:
                    successive_entries_check += 1

        except Exception as exc:
            logger.warn(
                "LDAP not yet initialised: {}; retrying in {} seconds".format(
                    exc, sleep_duration,
                )
            )
        time.sleep(sleep_duration)

    logger.error("LDAP not ready, after " + str(max_wait_time) + " seconds.")
    sys.exit(1)


def wait_for(manager, deps=None):
    deps = deps or []

    try:
        max_wait_time = int(os.environ.get("GLUU_WAIT_MAX_TIME", 300))
    except ValueError:
        max_wait_time = 300

    try:
        sleep_duration = int(os.environ.get("GLUU_WAIT_SLEEP_DURATION", 5))
    except ValueError:
        sleep_duration = 5

    if "config" in deps:
        wait_for_config(manager, max_wait_time, sleep_duration)

    if "secret" in deps:
        wait_for_secret(manager, max_wait_time, sleep_duration)

    if "ldap" in deps:
        wait_for_ldap(manager, max_wait_time, sleep_duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--deps", help="Comma-separated dependencies to wait for.")
    args = parser.parse_args()

    deps = set(filter(
        None,
        [dep.strip() for dep in args.deps.split(",") if dep]
    ))

    manager = get_manager()
    wait_for(manager, deps)
