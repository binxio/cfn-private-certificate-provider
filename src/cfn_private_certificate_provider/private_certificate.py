import boto3
import hashlib
from OpenSSL import crypto
from OpenSSL.SSL import FILETYPE_PEM
from cfn_resource_provider import ResourceProvider
from certauth.certauth import CertificateAuthority
from cfn_private_certificate_provider.ssm_cache import CertificateCache

request_schema = {
    "type": "object",
    "required": ["CAName", "Hostname"],
    "properties": {
        "CAName": {
            "type": "string",
            "description": "the name of the root CA",
            "pattern": "^[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9]$",
        },
        "Hostname": {
            "type": "string",
            "description": "to generate a certificate for",
            "pattern": "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)+([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$",
        },
        "Wildcard": {
            "description": "generate wildcard certificate",
            "type": "boolean",
            "default": False,
        },
        "RefreshOnUpdate": {
            "type": "boolean",
            "description": "refresh certificate on update",
            "default": False,
        },
    },
}


ssm = boto3.client("ssm")


class PrivateCertificateProvider(ResourceProvider):
    def __init__(self):
        super(ResourceProvider, self).__init__()
        self.request_schema = request_schema

    def convert_property_types(self):
        self.heuristic_convert_property_types(self.properties)
        self.heuristic_convert_property_types(self.old_properties)

    def is_valid_request(self):
        result = super(PrivateCertificateProvider, self).is_valid_request()
        if result:
            result = self.hostname not in ["root_ca", "!!root_ca"]
            if not result:
                self.fail("invalid Hostname")
        return result

    @property
    def ca_name(self):
        return self.get("CAName")

    @property
    def hostname(self):
        return self.get("Hostname")

    @property
    def wildcard(self):
        return self.get("Wildcard")

    @property
    def refresh_on_update(self):
        return self.get("RefreshOnUpdate")

    @property
    def old_ca_name(self):
        return self.get_old("CAName", self.ca_name)

    @property
    def old_hostname(self):
        return self.get_old("Hostname", self.hostname)

    @property
    def cache(self):
        return CertificateCache(ssm=ssm, ca_name=self.ca_name)

    def create_or_update(self, refresh=False):
        if not self.cache.get("!!root_ca"):
            self.fail(f"certificate for root ca '{self.ca_name}' does not exist.")
            return

        ca = CertificateAuthority(
            self.ca_name,
            ca_file_cache=self.cache,
            cert_cache=self.cache,
            overwrite=False,
        )

        cert, pkey, entry = ca.load_cert(
            self.hostname,
            overwrite=refresh,
            wildcard=self.wildcard,
            wildcard_use_parent=False,
            include_cache_key=True,
        )

        public_cert_pem = crypto.dump_certificate(FILETYPE_PEM, cert)
        self.set_attribute("CAName", self.ca_name)
        self.set_attribute("Hostname", self.hostname)
        self.set_attribute("Hash", hashlib.md5(public_cert_pem).hexdigest())
        self.set_attribute("PublicCertPEM", public_cert_pem.decode("ascii"))
        self.physical_resource_id = self.cache.parameter_name(self.hostname)

    def create(self):
        self.create_or_update(refresh=False)

    def update(self):
        if (
                self.ca_name != self.old_ca_name or self.hostname != self.old_hostname
        ) and self.cache.get(self.hostname):
            self.fail(
                f"certificate for host '{self.hostname}' in ca '{self.ca_name}' already exists."
            )
            return

        self.create_or_update(refresh=self.refresh_on_update)

    def delete(self):
        if not self.physical_resource_id.startswith("/certauth/"):
            self.success('ignore delete of resource not created')
            return

        cache = CertificateCache(ssm=ssm, ca_name=self.ca_name)
        cache.delete(self.hostname)


provider = PrivateCertificateProvider()


def handler(request, context):
    return provider.handle(request, context)
