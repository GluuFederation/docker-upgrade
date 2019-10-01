import itertools
import json
import re
import six

from backends import implode_dn
from backends import explode_dn

# INUM_REGEXES = [
#     re.compile(r'(!00[0-9a-fA-F][0-9a-fA-F]!)'),
#     re.compile(r'(![0-9a-fA-F]{4}\.)'),
#     re.compile(r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4})'),
#     re.compile(r'(00[0-9a-fA-F][0-9a-fA-F]-)'),
#     re.compile(r',\w+=,'),
# ]


# "scim.ldif",
# "oxidp.ldif",
# "oxtrust_api.ldif",
# "passport.ldif",
# "oxpassport-config.ldif",
# "gluu_radius_base.ldif",
# "gluu_radius_server.ldif",
# "clients.ldif",
# "oxtrust_api_clients.ldif",
# "scim_clients.ldif",
# "o_metric.ldif",
# "gluu_radius_clients.ldif",
# "passport_clients.ldif",
# "scripts_casa.ldif",


class Modifier(object):
    def __init__(self, manager):
        self.manager = manager
        self._inum_org = ""
        self._inum_appliance = ""

    @property
    def inum_org(self):
        if not self._inum_org:
            self._inum_org = self.manager.config.get("inumOrg")
        return self._inum_org

    @property
    def inum_appliance(self):
        if not self._inum_appliance:
            self._inum_appliance = self.manager.config.get("inumAppliance")
        return self._inum_appliance

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

    def should_process(self, dn, entry):
        raise NotImplementedError

    def process(self, dn, entry):
        raise NotImplementedError


class SiteModifier(Modifier):
    def should_process(dn, entry):
        return dn.endswith("o=site")

    def process(self, dn, entry):
        dn = self.transform_dn(dn)
        if dn.endswith("ou=people,o=site"):
            dn = dn.replace("ou=people,o=site",
                            "ou=cache-refresh,o=site")
        return dn, entry


class MetricModifier(Modifier):
    def should_process(dn, entry):
        return dn.endswith("o=metric")

    def process(self, dn, entry):
        dn = self.transform_dn(dn)
        return dn, entry


class GluuModifier(object):
    def __init__(self, manager):
        self.manager = manager
        self.modifiers = [
            _BaseModifier(self.manager),
            _AttributeModifier(self.manager),
            _ScopeModifier(self.manager),
            # _ScriptModifier(self.manager),
            _ConfigurationModifier(self.manager),
            _OxidpModifier(self.manager),
        ]

    def process(self, dn, entry):
        for mod in self.modifiers:
            if not mod.should_process(dn, entry):
                continue
            return mod.process(dn, entry)

        # no modification applied
        return "", None


class _BaseModifier(Modifier):
    """Modify entries base on base.ldif.
    """

    def should_process(self, dn, entry):
        dns = map(
            lambda f: f % {"inumOrg": self.inum_org},
            [
                # v4 doesn't need these entries
                # "o=gluu",
                # "ou=appliances,o=gluu",
                # "ou=hosts,o=%(inumOrg)s,o=gluu",
                # "ou=session,o=%(inumOrg)s,o=gluu",
                # "ou=scopes,ou=uma,o=%(inumOrg)s,o=gluu",
                "o=%(inumOrg)s,o=gluu",
                "ou=people,o=%(inumOrg)s,o=gluu",
                "ou=groups,o=%(inumOrg)s,o=gluu",
                "ou=attributes,o=%(inumOrg)s,o=gluu",
                "ou=scopes,o=%(inumOrg)s,o=gluu",
                "ou=clients,o=%(inumOrg)s,o=gluu",
                "ou=scripts,o=%(inumOrg)s,o=gluu",
                "ou=uma,o=%(inumOrg)s,o=gluu",
                "ou=resources,ou=uma,o=%(inumOrg)s,o=gluu",
                "ou=push,o=%(inumOrg)s,o=gluu",
                "ou=application,ou=push,o=%(inumOrg)s,o=gluu",
                "ou=device,ou=push,o=%(inumOrg)s,o=gluu",
                "ou=u2f,o=%(inumOrg)s,o=gluu",
                "ou=registration_requests,ou=u2f,o=%(inumOrg)s,o=gluu",
                "ou=authentication_requests,ou=u2f,o=%(inumOrg)s,o=gluu",
                "ou=registered_devices,ou=u2f,o=%(inumOrg)s,o=gluu",
                "ou=sector_identifiers,o=%(inumOrg)s,o=gluu",
            ]
        )
        return bool(dn in dns)

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


class _AttributeModifier(Modifier):
    """Modify entries base on attributes.ldif.
    """

    @property
    def saml2_uris(self):
        self._saml2_uris = getattr(self, "_saml2_uris", {})
        if not self._saml2_uris:
            with open("/app/templates/saml2_uri.json") as f:
                self._saml2_uris = json.loads(f.read())
        return self._saml2_uris

    def should_process(self, dn, entry):
        suffix = "ou=attributes,o=%(inumOrg)s,o=gluu" % {"inumOrg": self.inum_org}
        return dn.endswith(suffix)

    def process(self, dn, entry):
        dn = self.inum2id(self.transform_dn(dn))
        entry["inum"] = [self.inum2id(i) for i in entry["inum"]]
        entry["gluuSAML1URI"] = [
            "urn:mace:dir:attribute-def:{}".format(name)
            for name in entry["gluuAttributeName"]
        ]
        entry["gluuSAML2URI"] = self.saml2_uris.get(dn, [])
        return dn, entry


class _ScopeModifier(Modifier):
    """Modify entries base on scopes.ldif.
    """

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
        entry["oxId"] = entry.pop("displayName", [])
        entry["inum"] = [self.inum2id(i) for i in entry["inum"]]

        if "oxAuthClaim" in entry:
            entry["oxAuthClaim"] = [
                self.inum2id(c) for c in entry["oxAuthClaim"]
            ]

        if "oxScriptDn" in entry:
            entry["oxScriptDn"] = [
                self.inum2id(c) for c in entry["oxScriptDn"]
            ]
        return dn, entry


class _ScriptModifier(Modifier):
    """Modify entries base on scripts.ldif v3.
    """

    def should_process(self, dn, entry):
        suffix = "ou=scripts,o=%(inumOrg)s,o=gluu" % {"inumOrg": self.inum_org}
        return dn.endswith(suffix)

    def process(self, dn, entry):
        dn = self.inum2id(self.transform_dn(dn))
        return dn, entry


class _ConfigurationModifier(Modifier):
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

    def should_process(self, dn, entry):
        dns = map(lambda f: f % {"inumAppliance": self.inum_appliance}, [
            # v4 doesn't need these entries
            # "ou=configuration,inum=%(inumAppliance)s,ou=appliances,o=gluu",
            # "ou=oxasimba,ou=configuration,inum=%(inumAppliance)s,ou=appliances,o=gluu",
            "inum=%(inumAppliance)s,ou=appliances,o=gluu",
            "ou=trustRelationships,inum=%(inumAppliance)s,ou=appliances,o=gluu",
            "ou=federations,inum=%(inumAppliance)s,ou=appliances,o=gluu",
            "ou=oxauth,ou=configuration,inum=%(inumAppliance)s,ou=appliances,o=gluu",
            "ou=oxtrust,ou=configuration,inum=%(inumAppliance)s,ou=appliances,o=gluu",
            "ou=oxidp,ou=configuration,inum=%(inumAppliance)s,ou=appliances,o=gluu",
        ])
        return bool(dn in dns)

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


class _OxidpModifier(Modifier):
    def should_process(self, dn, entry):
        suffix = "ou=oxidp,o=%(inumOrg)s,o=gluu" % {"inumOrg": self.inum_org}
        return dn.endswith(suffix)

    def process(self, dn, entry):
        dn = self.transform_dn(dn)
        return dn, entry
