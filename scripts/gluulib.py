import base64
import json
import logging
import os
from collections import namedtuple

import hvac
import six
import kubernetes.client
import kubernetes.config
from consul import Consul

logger = logging.getLogger("gluulib")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fmt = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')
ch.setFormatter(fmt)
logger.addHandler(ch)


def as_boolean(val, default=False):
    """Converts value as boolean.
    """
    truthy = set(('t', 'T', 'true', 'True', 'TRUE', '1', 1, True))
    falsy = set(('f', 'F', 'false', 'False', 'FALSE', '0', 0, False))

    if val in truthy:
        return True
    if val in falsy:
        return False
    return default


def safe_value(value):
    if not isinstance(value, (six.string_types, six.binary_type)):
        value = json.dumps(value)
    return value


class BaseConfig(object):
    """Base class for config adapter. Must be sub-classed per
    implementation details.
    """
    type = "config"

    def get(self, key, default=None):
        """Get specific config.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError

    def set(self, key, value):
        """Set specific config.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError

    def all(self):
        """Get all config as ``dict`` type.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError


class ConsulConfig(BaseConfig):
    def __init__(self):
        # collects all env vars prefixed with `GLUU_CONFIG_CONSUL_`,
        # for example `GLUU_CONFIG_CONSUL_HOST=localhost`
        self.settings = {
            k: v for k, v in os.environ.iteritems()
            if k.isupper() and k.startswith("GLUU_CONFIG_CONSUL_")
        }

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_HOST",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_HOST", "localhost"),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_PORT",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_PORT", 8500),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_CONSISTENCY",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_CONSISTENCY", "stale"),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_SCHEME",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_SCHEME", "http"),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_VERIFY",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_VERIFY", False),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_CACERT_FILE",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_CACERT_FILE",
                           "/etc/certs/consul_ca.crt"),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_CERT_FILE",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_CERT_FILE",
                           "/etc/certs/consul_client.crt"),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_KEY_FILE",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_KEY_FILE",
                           "/etc/certs/consul_client.key"),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_CONSUL_TOKEN_FILE",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_CONSUL_TOKEN_FILE", "/etc/certs/consul_token"),
        )

        self.prefix = "gluu/config/"
        token = None
        cert = None
        verify = False

        if os.path.isfile(self.settings["GLUU_CONFIG_CONSUL_TOKEN_FILE"]):
            with open(self.settings["GLUU_CONFIG_CONSUL_TOKEN_FILE"]) as fr:
                token = fr.read().strip()

        if self.settings["GLUU_CONFIG_CONSUL_SCHEME"] == "https":
            verify = as_boolean(self.settings["GLUU_CONFIG_CONSUL_VERIFY"])

            # verify using CA cert (if any)
            if all([verify,
                    os.path.isfile(self.settings["GLUU_CONFIG_CONSUL_CACERT_FILE"])]):
                verify = self.settings["GLUU_CONFIG_CONSUL_CACERT_FILE"]

            if all([os.path.isfile(self.settings["GLUU_CONFIG_CONSUL_CERT_FILE"]),
                    os.path.isfile(self.settings["GLUU_CONFIG_CONSUL_KEY_FILE"])]):
                cert = (self.settings["GLUU_CONFIG_CONSUL_CERT_FILE"],
                        self.settings["GLUU_CONFIG_CONSUL_KEY_FILE"])

        self._request_warning(self.settings["GLUU_CONFIG_CONSUL_SCHEME"], verify)

        self.client = Consul(
            host=self.settings["GLUU_CONFIG_CONSUL_HOST"],
            port=self.settings["GLUU_CONFIG_CONSUL_PORT"],
            token=token,
            scheme=self.settings["GLUU_CONFIG_CONSUL_SCHEME"],
            consistency=self.settings["GLUU_CONFIG_CONSUL_CONSISTENCY"],
            verify=verify,
            cert=cert,
        )

    def _merge_path(self, key):
        """Add prefix to the key.
        """
        return "".join([self.prefix, key])

    def _unmerge_path(self, key):
        """Remove prefix from the key.
        """
        return key[len(self.prefix):]

    def get(self, key, default=None):
        _, result = self.client.kv.get(self._merge_path(key))
        if not result:
            return default
        return result["Value"]

    def set(self, key, value):
        return self.client.kv.put(self._merge_path(key),
                                  safe_value(value))

    def find(self, key):
        _, resultset = self.client.kv.get(self._merge_path(key),
                                          recurse=True)

        if not resultset:
            return {}

        return {
            self._unmerge_path(item["Key"]): item["Value"]
            for item in resultset
        }

    def all(self):
        return self.find("")

    def _request_warning(self, scheme, verify):
        if scheme == "https" and verify is False:
            import urllib3
            urllib3.disable_warnings()
            logger.warn(
                "All requests to Consul will be unverified. "
                "Please adjust GLUU_CONFIG_CONSUL_SCHEME and "
                "GLUU_CONFIG_CONSUL_VERIFY environment variables."
            )


class KubernetesConfig(BaseConfig):
    def __init__(self):
        self.settings = {
            k: v for k, v in os.environ.iteritems()
            if k.isupper() and k.startswith("GLUU_CONFIG_KUBERNETES_")
        }
        self.settings.setdefault(
            "GLUU_CONFIG_KUBERNETES_NAMESPACE",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_KUBERNETES_NAMESPACE", "default"),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_KUBERNETES_CONFIGMAP",
            # backward-compat with Gluu Server v3.1.4
            os.environ.get("GLUU_KUBERNETES_CONFIGMAP", "gluu"),
        )

        self.settings.setdefault(
            "GLUU_CONFIG_KUBERNETES_USE_KUBE_CONFIG",
            False
        )

        if as_boolean(self.settings["GLUU_CONFIG_KUBERNETES_USE_KUBE_CONFIG"]):
            kubernetes.config.load_kube_config()
        else:
            kubernetes.config.load_incluster_config()

        self.client = kubernetes.client.CoreV1Api()
        self.name_exists = False

    def get(self, key, default=None):
        result = self.all()
        return result.get(key, default)

    def _prepare_configmap(self):
        # create a configmap name if not exist
        if not self.name_exists:
            try:
                self.client.read_namespaced_config_map(
                    self.settings["GLUU_CONFIG_KUBERNETES_CONFIGMAP"],
                    self.settings["GLUU_CONFIG_KUBERNETES_NAMESPACE"])
                self.name_exists = True
            except kubernetes.client.rest.ApiException as exc:
                if exc.status == 404:
                    # create the configmaps name
                    body = {
                        "kind": "ConfigMap",
                        "apiVersion": "v1",
                        "metadata": {
                            "name": self.settings["GLUU_CONFIG_KUBERNETES_CONFIGMAP"],
                        },
                        "data": {},
                    }
                    created = self.client.create_namespaced_config_map(
                        self.settings["GLUU_CONFIG_KUBERNETES_NAMESPACE"],
                        body)
                    if created:
                        self.name_exists = True
                else:
                    raise

    def set(self, key, value):
        self._prepare_configmap()
        body = {
            "kind": "ConfigMap",
            "apiVersion": "v1",
            "metadata": {
                "name": self.settings["GLUU_CONFIG_KUBERNETES_CONFIGMAP"],
            },
            "data": {
                key: safe_value(value),
            }
        }
        return self.client.patch_namespaced_config_map(
            self.settings["GLUU_CONFIG_KUBERNETES_CONFIGMAP"],
            self.settings["GLUU_CONFIG_KUBERNETES_NAMESPACE"],
            body=body)

    def all(self):
        self._prepare_configmap()
        result = self.client.read_namespaced_config_map(
            self.settings["GLUU_CONFIG_KUBERNETES_CONFIGMAP"],
            self.settings["GLUU_CONFIG_KUBERNETES_NAMESPACE"])
        return result.data or {}


class ConfigManager(object):
    def __init__(self):
        _adapter = os.environ.get(
            "GLUU_CONFIG_ADAPTER",
            "consul",
        )
        if _adapter == "consul":
            self.adapter = ConsulConfig()
        elif _adapter == "kubernetes":
            self.adapter = KubernetesConfig()
        else:
            self.adapter = None

    def get(self, key, default=None):
        return self.adapter.get(key, default)

    def set(self, key, value):
        return self.adapter.set(key, value)

    def all(self):
        return self.adapter.all()


class BaseSecret(object):
    """Base class for secret adapter. Must be sub-classed per
    implementation details.
    """
    type = "secret"

    def get(self, key, default=None):
        """Get specific secret.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError

    def set(self, key, value):
        """Set specific secret.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError

    def all(self):
        """Get all secrets as ``dict`` type.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError


class VaultSecret(BaseSecret):
    def __init__(self):
        self.settings = {
            k: v for k, v in os.environ.iteritems()
            if k.isupper() and k.startswith("GLUU_SECRET_VAULT_")
        }
        self.settings.setdefault(
            "GLUU_SECRET_VAULT_HOST",
            "localhost",
        )
        self.settings.setdefault(
            "GLUU_SECRET_VAULT_PORT",
            8200,
        )
        self.settings.setdefault(
            "GLUU_SECRET_VAULT_SCHEME",
            "http",
        )
        self.settings.setdefault(
            "GLUU_SECRET_VAULT_VERIFY",
            False,
        )
        self.settings.setdefault(
            "GLUU_SECRET_VAULT_ROLE_ID_FILE",
            "/etc/certs/vault_role_id",
        ),
        self.settings.setdefault(
            "GLUU_SECRET_VAULT_SECRET_ID_FILE",
            "/etc/certs/vault_secret_id",
        )
        self.settings.setdefault(
            "GLUU_SECRET_VAULT_CERT_FILE",
            "/etc/certs/vault_client.crt",
        )
        self.settings.setdefault(
            "GLUU_SECRET_VAULT_KEY_FILE",
            "/etc/certs/vault_client.key",
        )
        self.settings.setdefault(
            "GLUU_SECRET_VAULT_CACERT_FILE",
            "/etc/certs/vault_ca.crt",
        )

        cert = None
        verify = False

        if self.settings["GLUU_SECRET_VAULT_SCHEME"] == "https":
            verify = as_boolean(self.settings["GLUU_SECRET_VAULT_VERIFY"])

            # verify using CA cert (if any)
            if all([verify,
                    os.path.isfile(self.settings["GLUU_SECRET_VAULT_CACERT_FILE"])]):
                verify = self.settings["GLUU_SECRET_VAULT_CACERT_FILE"]

            if all([os.path.isfile(self.settings["GLUU_SECRET_VAULT_CERT_FILE"]),
                    os.path.isfile(self.settings["GLUU_SECRET_VAULT_KEY_FILE"])]):
                cert = (self.settings["GLUU_SECRET_VAULT_CERT_FILE"],
                        self.settings["GLUU_SECRET_VAULT_KEY_FILE"])

        self._request_warning(self.settings["GLUU_SECRET_VAULT_SCHEME"], verify)

        self.client = hvac.Client(
            url="{}://{}:{}".format(
                self.settings["GLUU_SECRET_VAULT_SCHEME"],
                self.settings["GLUU_SECRET_VAULT_HOST"],
                self.settings["GLUU_SECRET_VAULT_PORT"],
            ),
            cert=cert,
            verify=verify,
        )
        self.prefix = "secret/gluu"

    @property
    def role_id(self):
        try:
            with open(self.settings["GLUU_SECRET_VAULT_ROLE_ID_FILE"]) as f:
                role_id = f.read()
        except IOError:
            role_id = ""
        return role_id

    @property
    def secret_id(self):
        try:
            with open(self.settings["GLUU_SECRET_VAULT_SECRET_ID_FILE"]) as f:
                secret_id = f.read()
        except IOError:
            secret_id = ""
        return secret_id

    def _authenticate(self):
        if self.client.is_authenticated():
            return

        creds = self.client.auth_approle(self.role_id, self.secret_id, use_token=False)
        self.client.token = creds["auth"]["client_token"]

    def get(self, key, default=None):
        self._authenticate()
        sc = self.client.read("{}/{}".format(self.prefix, key))
        if not sc:
            return default
        return sc["data"]["value"]

    def set(self, key, value):
        self._authenticate()
        val = {"value": value}

        # hvac.v1.Client.write checks for status code 200,
        # but Vault HTTP API returns 204 if request succeeded;
        # hence we're using lower level of `hvac.v1.Client` API to set key-val
        response = self.client._adapter.post('/v1/{0}/{1}'.format(self.prefix, key), json=val)
        return response.status_code == 204

    def all(self):
        self._authenticate()
        result = self.client.list(self.prefix)
        return {key: self.get(key) for key in result["data"]["keys"]}

    def _request_warning(self, scheme, verify):
        if scheme == "https" and verify is False:
            import urllib3
            urllib3.disable_warnings()
            logger.warn(
                "All requests to Vault will be unverified. "
                "Please adjust GLUU_SECRET_VAULT_SCHEME and "
                "GLUU_SECRET_VAULT_VERIFY environment variables."
            )


class KubernetesSecret(BaseSecret):
    def __init__(self):
        self.settings = {
            k: v for k, v in os.environ.iteritems()
            if k.isupper() and k.startswith("GLUU_SECRET_KUBERNETES_")
        }
        self.settings.setdefault(
            "GLUU_SECRET_KUBERNETES_NAMESPACE",
            "default",
        )
        self.settings.setdefault(
            "GLUU_SECRET_KUBERNETES_SECRET",
            "gluu",
        )
        self.settings.setdefault(
            "GLUU_SECRET_KUBERNETES_USE_KUBE_CONFIG",
            False
        )

        if as_boolean(self.settings["GLUU_SECRET_KUBERNETES_USE_KUBE_CONFIG"]):
            kubernetes.config.load_kube_config()
        else:
            kubernetes.config.load_incluster_config()
        self.client = kubernetes.client.CoreV1Api()
        self.name_exists = False

    def get(self, key, default=None):
        result = self.all()
        if key in result:
            return base64.b64decode(result[key])
        return default

    def _prepare_secret(self):
        # create a secret name if not exist
        if not self.name_exists:
            try:
                self.client.read_namespaced_secret(
                    self.settings["GLUU_SECRET_KUBERNETES_SECRET"],
                    self.settings["GLUU_SECRET_KUBERNETES_NAMESPACE"])
                self.name_exists = True
            except kubernetes.client.rest.ApiException as exc:
                if exc.status == 404:
                    # create the secrets name
                    body = {
                        "kind": "Secret",
                        "apiVersion": "v1",
                        "metadata": {
                            "name": self.settings["GLUU_SECRET_KUBERNETES_SECRET"],
                        },
                        "data": {},
                    }
                    created = self.client.create_namespaced_secret(
                        self.settings["GLUU_SECRET_KUBERNETES_NAMESPACE"],
                        body)
                    if created:
                        self.name_exists = True
                else:
                    raise

    def set(self, key, value):
        self._prepare_secret()
        body = {
            "kind": "Secret",
            "apiVersion": "v1",
            "metadata": {
                "name": self.settings["GLUU_SECRET_KUBERNETES_SECRET"],
            },
            "data": {
                key: base64.b64encode(value),
            }
        }
        return self.client.patch_namespaced_secret(
            self.settings["GLUU_SECRET_KUBERNETES_SECRET"],
            self.settings["GLUU_SECRET_KUBERNETES_NAMESPACE"],
            body=body)

    def all(self):
        self._prepare_secret()
        result = self.client.read_namespaced_secret(
            self.settings["GLUU_SECRET_KUBERNETES_SECRET"],
            self.settings["GLUU_SECRET_KUBERNETES_NAMESPACE"])
        return result.data or {}


class SecretManager(object):
    def __init__(self, config_adapter=None):
        _adapter = os.environ.get(
            "GLUU_SECRET_ADAPTER",
            "vault",
        )
        if _adapter == "vault":
            self.adapter = VaultSecret()
        elif _adapter == "kubernetes":
            self.adapter = KubernetesSecret()
        else:
            self.adapter = None

        # backward-compat
        self.config_adapter = config_adapter

    def _get_compat(self, key, default=None):
        sc = self.adapter.get(key, default)

        if not sc and self.config_adapter:
            # tries to get from old config
            sc = self.config_adapter.get(key, default)

        if not sc:
            # fallback to default
            sc = default
        return sc

    def get(self, key, default=None):
        return self._get_compat(key, default)

    def set(self, key, value):
        return self.adapter.set(key, value)

    def all(self):
        return self.adapter.all()


def get_manager():
    """Convenient function to get manager instances.
    """
    obj = namedtuple("Manager", "config secret")
    config_mgr = ConfigManager()
    secret_mgr = SecretManager(config_mgr)
    return obj(config=config_mgr, secret=secret_mgr)
