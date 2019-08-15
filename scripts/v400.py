import itertools
import logging
import json

from backends import LDAPBackend
from backends import implode_dn
from backends import explode_dn

logger = logging.getLogger("v400")


class Upgrade400(object):
    def __init__(self, manager):
        self.backend = LDAPBackend(manager)
        self.manager = manager
        self.version = "4.0.0"
        self.inum_org = ""
        self.inum_appliance = ""

    def prepare_inums(self):
        if not self.inum_org:
            self.inum_org = self.manager.config.get("inumOrg")

        if not self.inum_appliance:
            self.inum_appliance = self.manager.config.get("inumAppliance")

    def blacklist_entry(self, entry):
        # v4 doesn't support Asimba
        for s in ("ou=oxasimba", "!0011!D40C.1CA3"):
            if s in entry["dn"]:
                return True

        for oc in ('oxAsimbaConfiguration',
                   'oxAsimbaIDP',
                   'oxAsimbaRequestorPool',
                   'oxAsimbaSPRequestor',
                   'oxAsimbaSelector'):
            if oc in entry["attributes"]['objectClass']:
                return True

        # some oxAuth-related entries are no longer relevant in v4
        if "oxAuthGrant" in entry["attributes"]["objectClass"]:
            return True

        attrs = [
            'oxAuthExpiration',
            # 'oxAuthTokenCode',
            # 'oxTicket',
        ]
        for attr in attrs:
            if attr in entry["attributes"]:
                return True

        # UMA
        ou_checks = ('uma_permission', 'uma_rpt', 'clientAuthorizations')
        if "ou" in entry["attributes"] and entry["attributes"]['ou'][0] in ou_checks:
            return True

        # misc
        if any([entry["dn"].startswith("o=gluu"),
                entry["dn"].startswith("ou=appliances,o=gluu"),
                entry["dn"].startswith("ou=configuration"),
                entry["dn"].startswith("ou=cache")]):
            return True

        # the default flag
        return False

    def convert_dn(self, dn):
        # convert to sequence
        dns = explode_dn(dn)

        # remove inumOrg from DN (if any)
        inum_org_fmt = "o={}".format(self.inum_org)
        if inum_org_fmt in dns:
            dns.remove(inum_org_fmt)

        # remove inumAppliance from DN (if any)
        inum_appliance_fmt = "inum={}".format(self.inum_appliance)
        if inum_appliance_fmt in dns:
            dns.remove(inum_appliance_fmt)
            dns.remove("ou=appliances")

        # base gluuAppliance must use new ou
        if dn == "{},ou=appliances,o=gluu".format(inum_appliance_fmt):
            dns.insert(0, "ou=configuration")

        # convert to string
        return implode_dn(dns)

    @property
    def transform_callbacks(self):
        callbacks = {
            # new base config
            "ou=configuration,o=gluu": self.transform_base_config,
            # new oxAuth config
            "ou=oxauth,ou=configuration,o=gluu": self.transform_oxauth_config,
        }
        return callbacks

    def transform_entry(self, entry):
        entry["dn"] = self.convert_dn(entry["dn"])
        callback = self.transform_callbacks.get(entry["dn"])
        if callable(callback):
            entry = callback(entry)
        return entry

    def migrate_ldap_entries(self, key):
        total = 0
        for entry in self.backend.all(key):
            # skip unnecessary entry
            if self.blacklist_entry(entry):
                continue

            entry = self.transform_entry(entry)
            if entry["dn"] != entry["raw_dn"]:
                total += 1

        logger.info("total modified: {}".format(total))

    def run_upgrade(self):
        self.prepare_inums()
        keys = [
            "o=gluu",
            # "o=site",
            # "o=metric",
        ]
        for key in keys:
            self.migrate_ldap_entries(key)

    def transform_base_config(self, entry):
        entry["attributes"]["objectClass"].remove("gluuAppliance")
        entry["attributes"]['objectClass'].insert(1, 'gluuConfiguration')
        entry["attributes"]["ou"] = ["configuration"]
        entry["attributes"].pop("inum", None)

        auth = json.loads(entry["attributes"]['oxIDPAuthentication'][0])
        try:
            auth_config = json.loads(auth["config"])
        except TypeError:
            auth_config = auth['config']
        auth_config['baseDNs'][0] = 'ou=people,o=gluu'

        auth["config"] = auth_config
        entry["attributes"]["oxIDPAuthentication"][0] = json.dumps(auth)

        attrs = (
            'gluuPassportEnabled',
            'gluuManageIdentityPermission',
            'gluuOrgProfileMgt',
            'gluuScimEnabled',
            'gluuVdsCacheRefreshEnabled',
            'passwordResetAllowed',
        )
        for bool_attr in attrs:
            if bool_attr not in entry["attributes"]:
                continue

            if entry["attributes"][bool_attr][0] == 'enabled':
                entry["attributes"][bool_attr] = ['true']
            else:
                entry["attributes"][bool_attr] = ['false']

        ok, err = self.backend.add_entry(entry["dn"], entry["attributes"])
        if not ok:
            logger.error("unable to modify global config; reason={}".format(err))

        return entry

    def transform_oxauth_config(self, entry):
        # dynamic config of oxAuth as seen in oxauth-config.json
        dynamic_conf = json.loads(entry["attributes"]["oxAuthConfDynamic"][0])

        # attrs need to be added
        new_attrs = {
            "tokenRevocationEndpoint": "https://{}/oxauth/restv1/revoke".format(self.manager.config.get("hostname")),
            "responseModesSupported": ["query", "fragment", "form_post"],
            "cleanServiceBatchChunkSize": 1000,
        }

        for k, v in new_attrs.iteritems():
            if k in dynamic_conf:
                continue
            dynamic_conf[k] = v

        # attrs need to be modified
        mod_attrs = [
            "userInfoSigningAlgValuesSupported",
            "idTokenSigningAlgValuesSupported",
            "requestObjectSigningAlgValuesSupported",
            "tokenEndpointAuthSigningAlgValuesSupported",
        ]
        invalid_algs = ("PS256", "PS384", "PS512", "none")
        for attr in mod_attrs:
            dynamic_conf[attr] = [
                alg for alg in dynamic_conf[attr]
                if alg not in invalid_algs
            ]

        for value in dynamic_conf["authenticationFilters"]:
            value["baseDn"] = "ou=people,o=gluu"

        for value in dynamic_conf["clientAuthenticationFilters"]:
            value["baseDn"] = "ou=clients,o=gluu"

        # attrs need to be removed
        for attr in ["organizationInum", "applianceInum"]:
            dynamic_conf.pop(attr, None)

        entry["attributes"]["oxAuthConfDynamic"][0] = json.dumps(dynamic_conf)

        # static config of oxAuth as seen in oxauth-static-conf.json
        entry["attributes"]["oxAuthConfStatic"][0] = json.dumps({
            "baseDn": {
                "configuration": "ou=configuration,o=gluu",
                "people": "ou=people,o=gluu",
                "groups": "ou=groups,o=gluu",
                "clients": "ou=clients,o=gluu",
                "tokens": "ou=tokens,o=gluu",
                "scopes": "ou=scopes,o=gluu",
                "attributes": "ou=attributes,o=gluu",
                "scripts": "ou=scripts,o=gluu",
                "umaBase": "ou=uma,o=gluu",
                "umaPolicy": "ou=policies,ou=uma,o=gluu",
                "u2fBase": "ou=u2f,o=gluu",
                "metric": "ou=statistic,o=metric",
                "sectorIdentifiers": "ou=sector_identifiers,o=gluu",
            }
        })

        # static config of oxAuth as seen in oxauth-errors.json
        errors_conf = json.loads(entry["attributes"]["oxAuthConfErrors"][0])

        # get `retry` if any; if it's not found, add new one
        retry = list(itertools.ifilter(
            lambda x: x["id"] == "retry", errors_conf["authorize"]
        ))
        if not retry:
            errors_conf["authorize"].append({
                "id": "retry",
                "description": "The authorization server requires RP to send authorization request again.",
                "uri": None,
            })

        # change description of `invalid_grant_and_session`
        err_msg = "The provided id token (or access token) or " \
                  "session state are invalid or were issued " \
                  "to another client."
        for err in errors_conf["authorize"]:
            if err["id"] != "invalid_grant_and_session":
                continue
            if err["description"] != err_msg:
                err["description"] = err_msg

        # add `revoke`
        if "revoke" not in errors_conf:
            errors_conf["revoke"] = [
                {
                    "id": "unsupported_token_type",
                    "description": "The authorization server does not support the revocation "
                                   "of the presented token type. That is, the client tried to "
                                   "revoke an access token on a server not supporting this feature.",
                    "uri": None
                },
                {
                    "id": "invalid_request",
                    "description": "The request is missing a required parameter, includes an "
                                   "unsupported parameter or parameter value, repeats a parameter, "
                                   "includes multiple credentials, utilizes more than one mechanism "
                                   "for authenticating the client, or is otherwise malformed.",
                    "uri": None
                },
                {
                    "id": "invalid_client",
                    "description": "Client authentication failed (e.g. unknown client, no client authentication "
                                   "included, or unsupported authentication method). The authorization server "
                                   "MAY return an HTTP 401 (Unauthorized) status code to indicate which "
                                   "HTTP authentication schemes are supported. If the client attempted to "
                                   "authenticate via the Authorization request header field, the authorization "
                                   "server MUST respond with an HTTP 401 (Unauthorized) status code, "
                                   "and include the WWW-Authenticate response header field matching "
                                   "the authentication scheme used by the client.",
                    "uri": None,
                },
            ]

        entry["attributes"]["oxAuthConfErrors"][0] = json.dumps(errors_conf)

        ok, err = self.backend.add_entry(entry["dn"], entry["attributes"])
        if not ok:
            logger.error("unable to modify oxAuth config; reason={}".format(err))

        return entry
