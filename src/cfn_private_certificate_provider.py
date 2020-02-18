import boto3
from cfn_resource_provider import ResourceProvider
from certauth.certauth import CertificateAuthority
from ssm_cache import CertificateCache

request_schema = {
    "type": "object",
    "required": ["CAName", "Hostname"],
    "properties": {
       "CAName": {
            "type": "string",
            "description": "the name of the root CA",
           "pattern": "^[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9]$"
        },
        "Hostname": {
            "type": "string",
            "description": "to generate a certificate for",
            "pattern": "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)+([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$"
        },
       "Wildcard": {
            "description": "generate wildcard certificate",
           "type":  "boolean",
           "default": False
        }
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
        result = super(PrivateCertificateProvider,self).is_valid_request()
        if result:
            result = self.hostname not in [ 'root_ca', '!!root_ca']
            if not result:
                self.fail('invalid Hostname')
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
    def old_ca_name(self):
        return self.get_old("CAName", self.ca_name)

    @property
    def old_hostname(self):
        return self.get_old("Hostname", self.ca_name)

    def create_or_update(self, allow_overwrite=False):
        cache = CertificateCache(ssm=ssm, ca_name=self.ca_name)
        if not cache.get('!!root_ca'):
            self.fail(f"certificate for root ca '{self.ca_name}' does not exist.")
            return

        ca = CertificateAuthority(self.ca_name, ca_file_cache=cache, cert_cache=cache, overwrite=False)
        if not allow_overwrite and cache.get(self.hostname):
            self.fail(f"certificate for host '{self.hostname}' in ca '{self.ca_name}' already exists.")
            return

        _ = ca.cert_for_host(self.hostname, wildcard=self.wildcard, overwrite=False)
        self.physical_resource_id = cache.parameter_name(self.hostname)

    def create(self):
        self.create_or_update(allow_overwrite=False)

    def update(self):
        self.create_or_update(allow_overwrite=(self.ca_name == self.old_name and self.hostname == self.old_hostname))

    def delete(self):
        cache = CertificateCache(ssm=ssm, ca_name=self.ca_name)
        cache.delete(self.hostname)


provider = PrivateCertificateProvider()


def handler(request, context):
    return provider.handle(request, context)
