import logging
import logging.config

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

    def maybe_asimba(self, entry):
        """Determines whether entry is Asimba-related.
        """
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

    def maybe_oxauth(self, entry):
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

    def maybe_uma(self, entry):
        ou_checks = ('uma_permission', 'uma_rpt', 'clientAuthorizations')
        if "ou" in entry["attributes"] and entry["attributes"]['ou'][0] in ou_checks:
            return True

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

        # convert to string
        return implode_dn(dns)

    def migrate_ldap_entries(self, key):
        for entry in self.backend.all(key):
            # skip unnecessary entry
            if any([self.maybe_oxauth(entry),
                    self.maybe_asimba(entry),
                    self.maybe_uma(entry)]):
                continue

            logger.info("original: {}".format(entry["dn"]))
            entry["dn"] = self.convert_dn(entry["dn"])
            logger.info("modified: {}".format(entry["dn"]))

    def run_upgrade(self):
        self.prepare_inums()
        keys = [
            "o=gluu",
            # "o=site",
            # "o=metric",
        ]
        for key in keys:
            self.migrate_ldap_entries(key)
