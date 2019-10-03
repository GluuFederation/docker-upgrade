# import itertools
import logging
# import json
import os
import uuid

from ldif3 import LDIFParser

from pygluu.containerlib.utils import encode_text
from pygluu.containerlib.utils import exec_cmd

from backends import LDAPBackend
from modifiers import SiteModifier
from modifiers import MetricModifier
from modifiers import ModManager

SIG_KEYS = "RS256 RS384 RS512 ES256 ES384 ES512"
ENC_KEYS = "RSA_OAEP RSA1_5"

logger = logging.getLogger("v400")


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


class Upgrade400(object):
    def __init__(self, manager):
        self.backend = LDAPBackend(manager)
        self.manager = manager
        self.version = "4.0.0"

    def modify_site(self):
        file_ = "/app/imports/site.ldif"

        try:
            logger.info("Processing upgrade for o=site backend")
            parser = LDIFParser(open(file_))
            mod = SiteModifier(self.manager)

            for dn, entry in parser.parse():
                dn, entry = mod.process(dn, entry)
                if not dn:
                    continue

                modified, err = self.backend.upsert_entry(dn, entry)
                if not modified:
                    logger.warn(err)
        except IOError as exc:
            logger.warning("Unable to process upgrade for o=site backend; "
                           "reason={}".format(exc))

    def modify_metric(self):
        file_ = "/app/imports/metric.ldif"

        try:
            logger.info("Processing upgrade for o=metric backend")
            parser = LDIFParser(open(file_))
            mod = MetricModifier(self.manager)

            for dn, entry in parser.parse():
                dn, entry = mod.process(dn, entry)
                if not dn:
                    continue

                modified, err = self.backend.upsert_entry(dn, entry)
                if not modified:
                    logger.warn(err)
        except IOError as exc:
            logger.warning("Unable to process upgrade for o=metric backend; "
                           "reason={}".format(exc))

    def modify_user_root(self):
        file_ = "/app/imports/gluu.ldif"

        try:
            logger.info("Processing upgrade for o=gluu backend")
            parser = LDIFParser(open(file_))
            mod = ModManager(self.manager)

            for dn, entry in parser.parse():
                dn, entry = mod.process(dn, entry)
                if not dn:
                    continue

                # modified, err = self.backend.upsert_entry(dn, entry)
                # if not modified:
                #     logger.warn(err)

            # # the following entries are needed by Gluu Server v4
            # self.add_extra_entries()
        except IOError as exc:
            logger.warning("Unable to process upgrade for o=gluu backend; "
                           "reason={}".format(exc))

    def add_extra_entries(self):
        parser = LDIFParser(open("/app/templates/v4/extra_entries.ldif"))
        for dn, entry in parser.parse():
            entry = self.backend.get_entry(dn)
            if entry:
                continue

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

    def prepare_context(self):
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
                    "oxtrust_resource_id",
                    "gluu_radius_client_id",
                    "ox_radius_client_id"]:

            if not self.manager.config.get(key):
                self.manager.config.set(key, "0008-{}".format(uuid.uuid4()))

    def run_upgrade(self):
        # self.api_rs_context()
        # self.api_rp_context()
        self.prepare_context()

        # self.modify_site()
        # self.modify_metric()
        self.modify_user_root()
