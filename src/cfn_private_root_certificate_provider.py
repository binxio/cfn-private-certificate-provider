import boto3
from cfn_resource_provider import ResourceProvider
from certauth.certauth import CertificateAuthority
from OpenSSL import crypto
from OpenSSL.SSL import FILETYPE_PEM
from ssm_cache import CertificateCache
import hashlib

request_schema = {
    "type": "object",
    "required": ["CAName"],
    "properties": {
        "CAName": {
            "type": "string",
            "description": "the name of the root CA",
            "pattern": "^[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9]$",
        },
        "RefreshOnUpdate": {
            "type": "boolean",
            "description": "refresh root ca on update",
            "default": False,
        },
    },
}


ssm = boto3.client("ssm")


class PrivateRootCertificateProvider(ResourceProvider):
    def __init__(self):
        super(ResourceProvider, self).__init__()
        self.request_schema = request_schema

    def convert_property_types(self):
        self.heuristic_convert_property_types(self.properties)
        self.heuristic_convert_property_types(self.old_properties)

    @property
    def ca_name(self):
        return self.get("CAName")

    @property
    def old_ca_name(self):
        return self.get_old("CAName", self.ca_name)

    @property
    def public_key_parameter_name(self):
        return f"/certauth/{self.ca_name}/public-keys/root_ca"

    @property
    def cache(self):
        return CertificateCache(ssm=ssm, ca_name=self.ca_name)

    @property
    def refresh_on_update(self):
        return self.get("RefreshOnUpdate")

    def create_or_update(self, overwrite=False):
        ca = CertificateAuthority(
            self.ca_name, ca_file_cache=self.cache, cert_cache=self.cache, overwrite=overwrite
        )

        public_key_pem = crypto.dump_publickey(FILETYPE_PEM, ca.ca_cert.get_pubkey())
        self.set_attribute("CAName", self.ca_name)
        self.set_attribute("Hash", hashlib.md5(public_key_pem).hexdigest())
        self.set_attribute("PublicKeyPEM", public_key_pem.decode("ascii"))

        _ = ssm.put_parameter(
            Name=self.public_key_parameter_name,
            Value=self.get_attribute("PublicKeyPEM"),
            Overwrite=True,
            Type="String",
        )

        self.physical_resource_id = self.cache.parameter_name("!!root_ca")

    def create(self):
        self.create_or_update(overwrite=False)

    def update(self):
        if self.old_ca_name != self.ca_name and self.cache.get("!!root_ca"):
            self.fail(f"root certificate for ca '{self.ca_name}' already exists.")
            return

        self.create_or_update(overwrite=self.refresh_on_update)

    def delete(self):
        cache = CertificateCache(ssm=ssm, ca_name=self.ca_name)
        cache.delete("!!root_ca")

        try:
            _ = ssm.delete_parameter(Name=self.public_key_parameter_name)
        except ssm.exceptions.ParameterNotFound:
            pass


provider = PrivateRootCertificateProvider()


def handler(request, context):
    return provider.handle(request, context)
