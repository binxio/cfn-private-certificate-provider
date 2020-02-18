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
        }
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
    def public_key_parameter_name(self):
        return f'/certauth/{self.ca_name}/public-keys/root_ca'

    def create_or_update(self, allow_overwrite=False):
        cache = CertificateCache(ssm=ssm, ca_name=self.ca_name)
        if not allow_overwrite and cache.get("!!root_ca"):
            self.fail(f"root certificate for ca '{self.ca_name}' already exists.")
            return

        ca = CertificateAuthority(
            self.ca_name, ca_file_cache=cache, cert_cache=cache, overwrite=False
        )

        public_key_pem = crypto.dump_publickey(FILETYPE_PEM, ca.ca_cert.get_pubkey())
        self.set_attribute("Hash", hashlib.md5(public_key_pem).hexdigest())
        self.set_attribute("PublicKeyPEM", public_key_pem.decode("ascii"))

        _ = ssm.put_parameter(
            Name=self.public_key_parameter_name,
            Value=self.get_attribute("PublicKeyPEM"),
            Overwrite=True,
            Type="String",
        )

        self.physical_resource_id = cache.parameter_name('!!root_ca')

    def create(self):
        self.create_or_update(allow_overwrite=False)

    def update(self):
        self.create_or_update(allow_overwrite=(self.old_ca_name == self.ca_name))

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
