import json
import re

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
            # _AttributeModifier(self.manager),
            # _ScopeModifier(self.manager),
            # _ScriptModifier(self.manager),
            _ConfigurationModifier(self.manager),
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

        if dn == "o=gluu".format(self.inum_org):
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

    def transform_base_config(self, dn, entry):
        try:
            entry["objectClass"].remove("gluuAppliance")
        except ValueError:
            pass

        entry["objectClass"].append("gluuConfiguration")
        entry["ou"] = ["configuration"]
        entry["gluuRadiusEnabled"] = ["false"]
        entry["gluuSamlEnabled"] = ["false"]

        flags = [
            "gluuVdsCacheRefreshEnabled",
            "gluuOrgProfileMgt",
            "gluuManageIdentityPermission",
            "gluuVdsCacheRefreshEnabled",
            "gluuScimEnabled",
        ]
        for flag in flags:
            if flag not in entry:
                continue

            for i, status in enumerate(entry[flag]):
                entry[flag][i] = "true" if status == "enabled" else "false"

        auth = json.loads(entry["oxIDPAuthentication"][0])
        conf = json.loads(auth["config"])
        conf["baseDNs"] = ["ou=people,o=gluu"]
        auth["config"] = conf
        entry["oxIDPAuthentication"] = [json.dumps(auth)]

        entry.pop("inum", None)
        return dn, entry

    def process(self, dn, entry):
        dn = self.resolve_dn(dn)

        if dn == "ou=configuration,o=gluu":
            dn, entry = self.transform_base_config(dn, entry)
        print dn, entry
        return dn, entry
