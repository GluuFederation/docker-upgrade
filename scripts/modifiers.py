import abc
import itertools
import json
import re

import six

from backends import implode_dn
from backends import explode_dn


class Modifier(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, manager):
        self.manager = manager
        self.inum_org = self.manager.config.get("inumOrg")
        self.inum_appliance = self.manager.config.get("inumAppliance")

    @abc.abstractmethod
    def should_process(self, dn, entry):
        raise NotImplementedError

    @abc.abstractmethod
    def process(self, dn, entry):
        raise NotImplementedError

    def transform_dn(self, dn):
        dns = explode_dn(dn)

        strip_rdn = [
            "o={}".format(self.inum_org),
            "inum={}".format(self.inum_appliance),
            "ou={}".format(self.inum_appliance),
        ]
        for rdn in strip_rdn:
            try:
                dns.remove(rdn)
            except ValueError:
                pass
        return implode_dn(dns)

    def inum2id(self, s):
        tmps = s
        tmps = tmps.replace(self.inum_appliance, '')
        tmps = tmps.replace(self.inum_org, '')

        for x in re.findall(r'(!00[0-9a-fA-F][0-9a-fA-F]!)', tmps):
            tmps = tmps.replace(x, '')

        for x in re.findall(r'(![0-9a-fA-F]{4}\.)', tmps):
            tmps = tmps.replace(x, x.strip('!').strip('.') + '-')

        for x in re.findall(r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4})', tmps):
            tmps = tmps.replace(x, x.replace('.', '-'))

        for x in re.findall(r'(00[0-9a-fA-F][0-9a-fA-F]-)', tmps):
            tmps = tmps.replace(x, '')

        for x in re.findall(r',\w+=,', tmps):
            tmps = tmps.replace(x, ',')
        return tmps


class SiteModifier(Modifier):
    def should_process(self, dn, entry):
        return dn.endswith("o=site")

    def process(self, dn, entry):
        dn = self.transform_dn(dn)
        if dn.endswith("ou=people,o=site"):
            dn = dn.replace("ou=people,o=site",
                            "ou=cache-refresh,o=site")
        return dn, entry


class MetricModifier(Modifier):
    def should_process(self, dn, entry):
        return dn.endswith("o=metric")

    def process(self, dn, entry):
        dn = self.transform_dn(dn)
        return dn, entry


class BaseModifier(Modifier):
    """Modify root entry of ``o=gluu``.
    """

    def should_process(self, dn, entry):
        return dn == "o={},o=gluu".format(self.inum_org)

    def process(self, dn, entry):
        dn = self.transform_dn(dn)

        if dn == "o=gluu":
            entry["o"] = "gluu"
            entry["gluuManagerGroup"] = [
                self.transform_dn(group) for group in entry["gluuManagerGroup"]
            ]
            entry.pop("gluuAddPersonCapability", None)
            entry.pop("scimAuthMode", None)
            entry.pop("scimStatus", None)
        return dn, entry


class AttributeModifier(Modifier):
    """Modify entries under ``ou=attributes,o=gluu`` tree.
    """

    @property
    def saml2_uris(self):
        self._saml2_uris = getattr(self, "_saml2_uris", {})
        if not self._saml2_uris:
            with open("/app/templates/v4/saml2_uri.json") as f:
                self._saml2_uris = json.loads(f.read())
        return self._saml2_uris

    def should_process(self, dn, entry):
        suffix = "ou=attributes,o={},o=gluu".format(self.inum_org)
        return dn.endswith(suffix)

    def process(self, dn, entry):
        dn = self.inum2id(self.transform_dn(dn))

        if "inum" in entry:
            entry["inum"] = [self.inum2id(i) for i in entry["inum"]]

        if "gluuAttributeName" in entry:
            entry["gluuSAML1URI"] = [
                "urn:mace:dir:attribute-def:{}".format(name)
                for name in entry["gluuAttributeName"]
            ]
            entry["gluuSAML2URI"] = self.saml2_uris.get(dn, [])
        return dn, entry


class ScopeModifier(Modifier):
    """Modify entries under ``ou=scopes,o=gluu`` tree.
    """

    @property
    def suffix(self):
        return "ou=scopes,o={},o=gluu".format(self.inum_org)

    def resolve_dn(self, dn):
        dn = self.inum2id(self.transform_dn(dn))
        dns = []
        for d in explode_dn(dn):
            if d.startswith("inum"):
                d = d.split("-")[0]
            dns.append(d)
        dn = implode_dn(dns)
        return dn

    def should_process(self, dn, entry):
        suffix = "ou=scopes,o=%(inumOrg)s,o=gluu" % {"inumOrg": self.inum_org}
        return dn.endswith(suffix)

    def process(self, dn, entry):
        dn = self.resolve_dn(dn)

        if "displayName" in entry:
            entry["oxId"] = entry.pop("displayName", [])

        if "inum" in entry:
            entry["inum"] = [self.inum2id(i) for i in entry["inum"]]

        if "oxAuthClaim" in entry:
            entry["oxAuthClaim"] = [self.inum2id(c) for c in entry["oxAuthClaim"]]

        if "oxScriptDn" in entry:
            entry["oxScriptDn"] = [self.inum2id(c) for c in entry["oxScriptDn"]]

        if "oxId" in entry and entry["oxId"] == ["uma_protection"]:
            entry["displayName"] = ["UMA Protection"]
            entry["oxScopeType"] = ["openid"]
        return dn, entry


# @FIXME: conform to ce updater v4
class ScriptModifier(Modifier):
    """Modify entries under ``ou=scripts,o=gluu`` tree.
    """

    def should_process(self, dn, entry):
        suffix = "ou=scripts,o=%(inumOrg)s,o=gluu" % {"inumOrg": self.inum_org}
        return dn.endswith(suffix)

    def process(self, dn, entry):
        dn = self.inum2id(self.transform_dn(dn))
        return dn, entry


class ApplianceModifier(Modifier):
    """Modify entries under ``ou=appliances,o=gluu`` tree.
    """

    def resolve_dn(self, dn):
        dns = explode_dn(self.transform_dn(dn))
        try:
            dns.remove("ou=appliances")
        except ValueError:
            pass

        dn = implode_dn(dns)
        if dn == "o=gluu":
            dn = "ou=configuration,o=gluu"
        return dn

    def transform_base_config(self, entry):
        try:
            entry["objectClass"].remove("gluuAppliance")
        except ValueError:
            pass

        entry["objectClass"].append("gluuConfiguration")
        entry["ou"] = ["configuration"]

        for e in ["gluuRadiusEnabled", "gluuSamlEnabled"]:
            if e in entry:
                continue
            entry[e] = ["false"]

        flags = [
            "gluuVdsCacheRefreshEnabled",
            "gluuOrgProfileMgt",
            "gluuManageIdentityPermission",
            "gluuVdsCacheRefreshEnabled",
            "gluuScimEnabled",
            "gluuPassportEnabled",
            "passwordResetAllowed",
        ]
        for flag in flags:
            if flag not in entry:
                continue

            status = entry[flag][0]
            if status.lower() in ("true", "enabled"):
                status = "true"
            else:
                status = "false"
            entry[flag][0] = status

        auth = json.loads(entry["oxIDPAuthentication"][0])
        try:
            auth_config = json.loads(auth["config"])
        except TypeError:
            auth_config = auth["config"]
        auth_config["baseDNs"][0] = "ou=people,o=gluu"

        auth["config"] = auth_config
        entry["oxIDPAuthentication"] = [json.dumps(auth)]

        entry.pop("inum", None)
        return entry

    def transform_oxauth_config(self, entry):
        # dynamic config of oxAuth as seen in oxauth-config.json
        dynamic_conf = json.loads(entry["oxAuthConfDynamic"][0])

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

        entry["oxAuthConfDynamic"][0] = json.dumps(dynamic_conf)

        # static config of oxAuth as seen in oxauth-static-conf.json
        entry["oxAuthConfStatic"][0] = json.dumps({
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
        errors_conf = json.loads(entry["oxAuthConfErrors"][0])

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

        entry["oxAuthConfErrors"][0] = json.dumps(errors_conf)
        return entry

    def transform_oxtrust_config(self, entry):
        # oxTrust app config as seen in oxtrust-config.json
        app_conf = json.loads(entry["oxTrustConfApplication"][0])

        # attrs need to be removed
        for attr in ["orgInum", "applianceInum"]:
            app_conf.pop(attr, None)

        # attrs need to be modified
        app_conf["photoRepositoryRootDir"] = "/var/gluu/photos"
        app_conf["logoLocation"] = "/var/gluu/photos"
        app_conf["ldifStore"] = "/var/gluu/identity/removed"
        app_conf["loginRedirectUrl"] = "https://{}/identity/authcode.htm".format(
            self.manager.config.get("hostname")
        )
        app_conf["logoutRedirectUrl"] = "https://{}/identity/finishlogout.htm".format(
            self.manager.config.get("hostname")
        )

        # attrs need to be added
        new_attrs = {
            "applicationUrl": app_conf.pop("applianceUrl", ""),
            "updateStatus": app_conf.pop("updateApplianceStatus", ""),
            "oxTrustApiTestMode": False,
            "apiUmaClientId": self.manager.config.get("oxtrust_resource_server_client_id"),
            "apiUmaClientKeyId": "",
            "apiUmaResourceId": self.manager.config.get("oxtrust_resource_id"),
            "apiUmaScope": "https://{}/oxauth/restv1/uma/scopes/oxtrust-api-read".format(self.manager.config.get("hostname")),
            "apiUmaClientKeyStoreFile": self.manager.config.get("api_rs_client_jks_fn"),
            "apiUmaClientKeyStorePassword": self.manager.secret.get("api_rs_client_jks_pass_encoded"),
        }

        app_conf.update({
            k: v for k, v in six.iteritems(new_attrs)
            if k not in app_conf
        })

        entry["oxTrustConfApplication"][0] = json.dumps(app_conf)

        # oxTrust cache-refresh config as seen in oxtrust-cache-refresh.json
        cr_conf = json.loads(entry["oxTrustConfCacheRefresh"][0])
        cr_conf["inumConfig"]["baseDNs"][0] = "ou=cache-refresh,o=site"
        cr_conf["snapshotFolder"] = "/var/gluu/identity/cr-snapshots"

        entry["oxTrustConfCacheRefresh"][0] = json.dumps(cr_conf)
        return entry

    def should_process(self, dn, entry):
        blacklisted = [
            "ou=appliances,o=gluu",
            "ou=configuration,inum={},ou=appliances,o=gluu".format(self.inum_appliance),
            "ou=oxasimba,ou=configuration,inum={},ou=appliances,o=gluu".format(self.inum_appliance),
        ]
        return all([dn.endswith("ou=appliances,o=gluu"), dn not in blacklisted])

    def process(self, dn, entry):
        dn = self.resolve_dn(dn)

        callbacks = {
            "ou=configuration,o=gluu": self.transform_base_config,
            "ou=oxauth,ou=configuration,o=gluu": self.transform_oxauth_config,
            "ou=oxtrust,ou=configuration,o=gluu": self.transform_oxtrust_config,
        }
        callback = callbacks.get(dn)

        if callable(callback):
            entry = callback(entry)
        return dn, entry


class OxidpModifier(Modifier):
    """Modify entries under ``ou=oxidp,o=gluu`` tree.
    """

    def should_process(self, dn, entry):
        suffix = "ou=oxidp,o={},o=gluu".format(self.inum_org)
        return dn.endswith(suffix)

    def process(self, dn, entry):
        dn = self.transform_dn(dn)
        return dn, entry


class SectorIdentifierModifier(Modifier):
    """Modify entries under ``ou=sector_identifier,o=gluu`` tree.
    """

    def should_process(self, dn, entry):
        suffix = "ou=sector_identifiers,o={},o=gluu".format(self.inum_org)
        return dn.endswith(suffix)

    def process(self, dn, entry):
        dn = self.transform_dn(dn)
        return dn, entry


class ClientModifier(Modifier):
    """Modify entries under ``ou=clients,o=gluu`` tree.
    """

    @property
    def context(self):
        self._context = getattr(self, "_context", {
            "oxauth_client_id": self.manager.config.get("oxauth_client_id"),
            "hostname": self.manager.config.get("hostname"),
            "idp_client_id": self.manager.config.get("idp_client_id"),
            "scim_rp_client_id": self.manager.config.get("scim_rp_client_id"),
            "passport_rp_client_id": self.manager.config.get("passport_rp_client_id"),
        })
        return self._context

    def should_process(self, dn, entry):
        suffix = "ou=clients,o={},o=gluu".format(self.inum_org)
        has_suffix = dn.endswith(suffix)
        no_grant = "oxAuthGrant" not in entry["objectClass"]
        # no_asimba = "ou=oxasimba" not in dn
        # no_inbound_saml = "!0011!D40C.1CA3" not in dn
        no_nonce = "oxAuthNonce" not in entry

        if all([has_suffix,
                no_grant,
                no_nonce,
                # no_asimba,
                # no_inbound_saml,
                ]):
            return True
        return False

    def transform_oxtrust(self, entry):
        hostname = self.context["hostname"]

        entry["oxAuthLogoutURI"] = [
            "https://{}/identity/ssologout.htm".format(hostname)
        ]
        entry["oxAuthPostLogoutRedirectURI"] = [
            "https://{}/identity/finishlogout.htm".format(hostname)
        ]

        # uri need to be removed
        del_uris = [
            "https://{}/identity/authentication/getauthcode".format(hostname),
            "https://{}/cas/login".format(hostname)
        ]
        for uri in del_uris:
            try:
                entry["oxAuthRedirectURI"].remove(uri)
            except ValueError:
                pass

        # modify authcode
        try:
            idx = entry["oxAuthRedirectURI"].index(
                "https://{}/identity/authentication/authcode".format(hostname)
            )
            entry["oxAuthRedirectURI"][idx] = "https://{}/identity/authcode.htm".format(hostname)
        except ValueError:
            pass
        return entry

    def process(self, dn, entry):
        dn = self.transform_dn(dn)

        if dn == "inum={},ou=clients,o=gluu".format(self.context["oxauth_client_id"]):
            entry = self.transform_oxtrust(entry)

        if dn == "inum={},ou=clients,o=gluu".format(self.context["scim_rp_client_id"]):
            entry.pop("oxAuthScope", None)

        if dn == "inum={},ou=clients,o=gluu".format(self.context["passport_rp_client_id"]):
            entry.pop("oxAuthScope", None)

        if "oxAuthScope" in entry:
            entry["oxAuthScope"] = [self.inum2id(s) for s in entry["oxAuthScope"]]
        return dn, entry


class PeopleModifier(Modifier):
    """Modify entries under ``ou=people,o=gluu`` tree.
    """

    @property
    def context(self):
        self._context = getattr(self, "_context", {
            "admin_inum": self.manager.config.get("admin_inum"),
        })
        return self._context

    def should_process(self, dn, entry):
        suffix = "ou=people,o={},o=gluu".format(self.inum_org)
        return dn.endswith(suffix)

    def process(self, dn, entry):
        dn = self.transform_dn(dn)

        try:
            if entry["uid"] == ["admin"]:
                dn = "inum={},ou=people,o=gluu".format(self.context["admin_inum"])
                entry["inum"] = [self.context["admin_inum"]]
            entry["memberOf"] = [self.inum2id(m) for m in entry["memberOf"]]
        except KeyError:
            pass
        return dn, entry


class GroupModifier(Modifier):
    """Modify entries under ``ou=groups,o=gluu`` tree.
    """

    @property
    def context(self):
        self._context = getattr(self, "_context", {
            "admin_inum": self.manager.config.get("admin_inum"),
        })
        return self._context

    def should_process(self, dn, entry):
        suffix = "ou=groups,o={},o=gluu".format(self.inum_org)
        return dn.endswith(suffix)

    def process(self, dn, entry):
        dn = self.inum2id(self.transform_dn(dn))

        if "member" in entry:
            try:
                # migrate admin user
                idx = entry["member"].index(
                    "inum={0}!0000!A8F2.DE1E.D7FB,ou=people,o={0},o=gluu".format(self.inum_org)
                )
                entry["member"][idx] = "inum={},ou=people,o=gluu".format(self.context["admin_inum"])
            except ValueError:
                pass

        if "inum" in entry:
            entry["inum"] = [self.inum2id(inum) for inum in entry["inum"]]
        return dn, entry


class PushModifier(Modifier):
    def should_process(self, dn, entry):
        suffix = "ou=push,o={},o=gluu".format(self.inum_org)
        return dn.endswith(suffix)

    def process(self, dn, entry):
        dn = self.transform_dn(dn)
        return dn, entry


class UmaModifier(Modifier):
    @property
    def context(self):
        self._context = getattr(self, "_context", {
            "passport_resource_id": self.manager.config.get("passport_resource_id"),
            "scim_resource_oxid": self.manager.config.get("scim_resource_oxid"),
            "admin_inum": self.manager.config.get("admin_inum"),
            "passport_rs_client_id": self.manager.config.get("passport_rs_client_id"),
        })
        return self._context

    def should_process(self, dn, entry):
        blacklisted = [
            "ou=scopes,ou=uma,o={},o=gluu".format(self.inum_org),
        ]
        suffix = "ou=uma,o={},o=gluu".format(self.inum_org)
        return all([dn.endswith(suffix), dn not in blacklisted])

    def resolve_scope(self, scope):
        dns = explode_dn(self.inum2id(scope))
        if "ou=uma" in dns:
            dns.remove("ou=uma")
        return implode_dn(dns)

    def transform_passport_resource(self, entry):
        entry["owner"] = ["inum={},ou=people,o=gluu".format(self.context["admin_inum"])]
        entry["oxId"] = [self.context["passport_resource_id"]]
        entry["oxAssociatedClient"] = ["inum={},ou=clients,o=gluu".format(self.context["passport_rs_client_id"])]
        entry["oxAuthUmaScope"] = [self.resolve_scope(s) for s in entry["oxAuthUmaScope"]]
        return entry

    def transform_scim_resource(self, entry):
        entry["owner"] = ["inum={},ou=people,o=gluu".format(self.context["admin_inum"])]
        entry["oxId"] = [self.context["scim_resource_oxid"]]
        entry["oxAssociatedClient"] = ["inum={},ou=clients,o=gluu".format(self.context["scim_rs_client_id"])]
        entry["oxAuthUmaScope"] = [self.resolve_scope(s) for s in entry["oxAuthUmaScope"]]
        return entry

    def transform_scope(self, entry):
        entry.pop("owner", None)
        entry.pop("oxRevision", None)
        entry["oxScopeType"] = ["uma"]
        entry["objectClass"] = ["top", "oxAuthCustomScope"]
        entry["oxUmaPolicyScriptDn"] = [
            self.inum2id(s)
            for s in entry.pop("oxPolicyScriptDn", [])
        ]
        return entry

    def process(self, dn, entry):
        dn = self.inum2id(self.transform_dn(dn))

        if "inum" in entry:
            entry["inum"] = [self.inum2id(i) for i in entry["inum"]]

        if dn == "oxId=1543d9aa-035d-4a84-a1ca-c8a230054540,ou=resources,ou=uma,o=gluu":
            dn = "oxId={},ou=resources,ou=uma,o=gluu".format(self.context["passport_resource_id"])
            entry = self.transform_scim_resource(entry)

        if dn == "oxId=0f963ecc-93f0-49c1-beae-ad2006abbb99,ou=resources,ou=uma,o=gluu":
            dn = "oxId={},ou=resources,ou=uma,o=gluu".format(self.context["passport_resource_id"])
            entry = self.transform_passport_resource(entry)

        # migrate ou=scopes,ou=uma to ou=scopes
        if "oxAuthUmaScopeDescription" in entry["objectClass"]:
            dn = dn.replace("ou=uma,", "")
            entry = self.transform_scope(entry)
        return dn, entry


class U2fModifier(Modifier):
    def should_process(self, dn, entry):
        suffix = "ou=u2f,o={},o=gluu".format(self.inum_org)
        return dn.endswith(suffix)

    def process(self, dn, entry):
        dn = self.transform_dn(dn)
        return dn, entry


class ModManager(object):
    # "ou=hosts,o=%(inumOrg)s,o=gluu",
    # "ou=session,o=%(inumOrg)s,o=gluu",

    def __init__(self, manager):
        self.manager = manager
        self.modifiers = map(lambda mod: mod(self.manager), [
            # BaseModifier,
            # ApplianceModifier,
            # AttributeModifier,
            # ScopeModifier,
            # ScriptModifier,
            # OxidpModifier,
            # ClientModifier,
            # SectorIdentifierModifier,
            # GroupModifier,
            # PeopleModifier,
            # PushModifier,
            # UmaModifier,
            U2fModifier,
        ])

    def process(self, dn, entry):
        for mod in self.modifiers:
            if not mod.should_process(dn, entry):
                continue
            return mod.process(dn, entry)

        # no modification applied
        return "", None
