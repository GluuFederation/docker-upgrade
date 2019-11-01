# import itertools
import logging
import json
import os
import uuid

from ldif3 import LDIFParser

from pygluu.containerlib.utils import decode_text
from pygluu.containerlib.utils import encode_text
from pygluu.containerlib.utils import exec_cmd
from pygluu.containerlib.utils import get_random_chars
from pygluu.containerlib.utils import generate_base64_contents

from backends import LDAPBackend
from modifiers import ModManager

SIG_KEYS = "RS256 RS384 RS512 ES256 ES384 ES512"
ENC_KEYS = "RSA_OAEP RSA1_5"

logger = logging.getLogger("v40")


def generate_openid_keys(passwd, jks_path, jwks_path, dn, exp=365):
    if os.path.isfile(jks_path):
        os.unlink(jks_path)

    cmd = " ".join([
        "java",
        "-Dlog4j.defaultInitOverride=true",
        "-jar", "/app/javalibs/oxauth-client.jar",
        "-enc_keys", ENC_KEYS,
        "-sig_keys", SIG_KEYS,
        "-dnname", "{!r}".format(dn),
        "-expiration", "{}".format(exp),
        "-keystore", jks_path,
        "-keypasswd", passwd,
    ])
    out, err, retcode = exec_cmd(cmd)
    if retcode == 0:
        with open(jwks_path, "w") as f:
            f.write(out)
    return out, err, retcode


class Upgrade40(object):
    def __init__(self, manager):
        self.backend = LDAPBackend(manager)
        self.manager = manager
        self.version = "4.0"

    def modify_entries(self):
        file_mappings = [
            ("/app/imports/gluu.ldif", "userRoot"),
            ("/app/imports/site.ldif", "site"),
            ("/app/imports/metric.ldif", "metric"),
        ]

        for file_, backend in file_mappings:
            try:
                logger.info("Loading entries from {} "
                            "for {} backend".format(file_, backend))
                parser = LDIFParser(open(file_))
                mod = ModManager(self.manager)

                for dn, entry in parser.parse():
                    dn, entry = mod.process(dn, entry)
                    if not dn:
                        continue

                    modified, err = self.backend.upsert_entry(dn, entry)
                    if not modified:
                        logger.warn(err)
            except IOError as exc:
                logger.warning("Unable to modify entries for {} backend; "
                               "reason={}".format(backend, exc))

    def add_extra_entries(self):
        # radius scripts
        with open("/app/templates/v4/super_gluu_ro.py") as f:
            super_gluu_ro_script = generate_base64_contents(f.read())

        with open("/app/templates/v4/super_gluu_ro_session.py") as f:
            super_gluu_ro_session_script = generate_base64_contents(f.read())

        # casa scripts
        with open("/app/templates/v4/person_authentication_casa.py") as f:
            person_authentication_casa = generate_base64_contents(f.read())

        with open("/app/templates/v4/client_registration_casa.py") as f:
            client_registration_casa = generate_base64_contents(f.read())

        ctx = {
            "hostname": self.manager.config.get("hostname"),
            "gluu_radius_client_id": self.manager.config.get("gluu_radius_client_id"),
            "enableRadiusScripts": "false",
            "super_gluu_ro_session_script": super_gluu_ro_session_script,
            "super_gluu_ro_script": super_gluu_ro_script,
            "gluu_ro_encoded_pw": self.manager.secret.get("gluu_ro_encoded_pw"),
            "gluu_ro_client_base64_jwks": generate_base64_contents(self.manager.secret.get("gluu_ro_client_base64_jwks")),
            "person_authentication_casa": person_authentication_casa,
            "client_registration_casa": client_registration_casa,
        }

        with open("/app/templates/v4/extra_entries.ldif") as f:
            txt = f.read() % ctx

            with open("/tmp/extra_entries.ldif", "w") as fw:
                fw.write(txt)

        parser = LDIFParser(
            open("/tmp/extra_entries.ldif"),
        )
        for dn, entry in parser.parse():
            _, err = self.backend.add_entry(dn, entry)
            if err:
                logger.warn(err)

    def set_config(self, key, value):
        if not self.manager.config.get(key):
            self.manager.config.set(key, value)

    def set_secret(self, key, value):
        if not self.manager.secret.get(key):
            self.manager.secret.set(key, value)

    def api_rs_context(self):
        self.set_config("api_rs_client_jks_fn", "/etc/certs/api-rs.jks")
        self.set_config("api_rs_client_jwks_fn", "/etc/certs/api-rs-keys.json")
        self.set_secret("api_rs_client_jks_pass", "secret")

        api_rs_client_jks_pass = self.manager.secret.get("api_rs_client_jks_pass")
        api_rs_client_jks_fn = self.manager.config.get("api_rs_client_jks_fn")
        api_rs_client_jwks_fn = self.manager.config.get("api_rs_client_jwks_fn")

        self.set_secret(
            "api_rs_client_jks_pass_encoded",
            encode_text(
                api_rs_client_jks_pass,
                self.manager.secret.get("encoded_salt"),
            ),
        )

        self.set_config("oxtrust_resource_server_client_id", '0008-{}'.format(uuid.uuid4()))
        self.set_config("oxtrust_resource_id", '0008-{}'.format(uuid.uuid4()))

        _, err, retcode = generate_openid_keys(
            api_rs_client_jks_pass,
            api_rs_client_jks_fn,
            api_rs_client_jwks_fn,
            self.manager.config.get("default_openid_jks_dn_name"),
        )
        assert retcode == 0, "Unable to generate oxTrust API RS keys; reason={}".format(err)

        if not self.manager.secret.get("api_rs_client_base64_jwks"):
            self.manager.secret.from_file(
                "api_rs_client_base64_jwks",
                api_rs_client_jwks_fn,
                encode=True,
            )

        if not self.manager.secret.get("api_rs_jks_base64"):
            self.manager.secret.from_file(
                "api_rs_jks_base64",
                api_rs_client_jks_fn,
                encode=True,
            )

    def api_rp_context(self):
        self.set_config("api_rp_client_jks_fn", "/etc/certs/api-rp.jks")
        self.set_config("api_rp_client_jwks_fn", "/etc/certs/api-rp-keys.json")
        self.set_secret("api_rp_client_jks_pass", "secret")

        api_rp_client_jks_pass = self.manager.secret.get("api_rp_client_jks_pass")
        api_rp_client_jks_fn = self.manager.config.get("api_rp_client_jks_fn")
        api_rp_client_jwks_fn = self.manager.config.get("api_rp_client_jwks_fn")

        self.set_secret(
            "api_rp_client_jks_pass_encoded",
            encode_text(
                api_rp_client_jks_pass,
                self.manager.secret.get("encoded_salt"),
            ),
        )

        self.set_config("oxtrust_requesting_party_client_id", '0008-{}'.format(uuid.uuid4()))

        _, err, retcode = generate_openid_keys(
            api_rp_client_jks_pass,
            api_rp_client_jks_fn,
            api_rp_client_jwks_fn,
            self.manager.config.get("default_openid_jks_dn_name"),
        )
        assert retcode == 0, "Unable to generate oxTrust API RP keys; reason={}".format(err)

        if not self.manager.secret.get("api_rp_client_base64_jwks"):
            self.manager.secret.from_file(
                "api_rp_client_base64_jwks",
                api_rp_client_jwks_fn,
                encode=True,
            )

        if not self.manager.secret.get("api_rp_jks_base64"):
            self.manager.secret.from_file(
                "api_rp_jks_base64",
                api_rp_client_jks_fn,
                encode=True,
            )

    def radius_context(self):
        self.set_config("gluu_radius_client_id", '0008-{}'.format(uuid.uuid4()))
        self.set_config("ox_radius_client_id", '0008-{}'.format(uuid.uuid4()))

        self.set_secret(
            "gluu_ro_encoded_pw",
            encode_text(get_random_chars(), self.manager.secret.get("encoded_salt")),
        )

        self.set_secret(
            "radius_jwt_pass",
            encode_text(get_random_chars(), self.manager.secret.get("encoded_salt")),
        )
        radius_jwt_pass = self.manager.secret.get("radius_jwt_pass")

        secrets_avail = all([
            self.manager.secret.get("radius_jks_base64"),
            self.manager.secret.get("gluu_ro_client_base64_jwks"),
            self.manager.secret.get("radius_jwt_keyId"),
        ])

        if secrets_avail:
            # nothing to do
            return

        out, err, retcode = generate_openid_keys(
            decode_text(radius_jwt_pass, self.manager.secret.get("encoded_salt")),
            "/etc/certs/gluu-radius.jks",
            "/etc/certs/gluu-radius.keys",
            self.manager.config.get("default_openid_jks_dn_name"),
        )
        assert retcode == 0, "Unable to generate Gluu Radius keys; reason={}".format(err)

        for key in json.loads(out)["keys"]:
            if key["alg"] == "RS512":
                self.manager.config.set("radius_jwt_keyId", key["kid"])
                break

        if not self.manager.secret.get("radius_jks_base64"):
            self.manager.secret.from_file(
                "radius_jks_base64",
                "/etc/certs/gluu-radius.jks",
                encode=True,
            )

        if not self.manager.secret.get("gluu_ro_client_base64_jwks"):
            self.manager.secret.from_file(
                "gluu_ro_client_base64_jwks",
                "/etc/certs/gluu-radius.keys",
            )

    def prepare_context(self):
        self.api_rs_context()
        self.api_rp_context()
        self.radius_context()

        if not self.manager.config.get("admin_inum"):
            self.manager.config.set("admin_inum", "{}".format(uuid.uuid4()))

        # create or modify client IDs
        for key in ["oxauth_client_id",
                    "idp_client_id",
                    "scim_rp_client_id",
                    "scim_rs_client_id",
                    "passport_resource_id",
                    "passport_rp_client_id",
                    "passport_rs_client_id",
                    "passport_rp_ii_client_id",
                    "oxtrust_resource_server_client_id",
                    "oxtrust_resource_id"]:
            if not self.manager.config.get(key):
                self.manager.config.set(key, "0008-{}".format(uuid.uuid4()))

    def run_upgrade(self):
        logger.info("Preparing config and secret")
        self.prepare_context()

        logger.info("Processing existing LDAP entries")
        self.modify_entries()

        logger.info("Adding misc LDAP entries")
        self.add_extra_entries()

        return True
