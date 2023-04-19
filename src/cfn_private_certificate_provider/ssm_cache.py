class CertificateCache(object):
    def __init__(self, ssm: object, ca_name: str):
        super(CertificateCache, self).__init__()
        self.ssm = ssm
        self.ca_name = ca_name
        self.certificates_path = f"/certauth/{self.ca_name}/private/"

    def __setitem__(self, host, cert_string):
        host = "root_ca" if host == "!!root_ca" else host
        value = cert_string.decode("ascii")
        self.ssm.put_parameter(
            Name=f"{self.certificates_path}{host}",
            Value=value,
            Overwrite=True,
            Type="SecureString",
        )

    def get(self, host):
        host = "root_ca" if host == "!!root_ca" else host
        name = f"{self.certificates_path}{host}"
        try:
            response = self.ssm.get_parameter(Name=name, WithDecryption=True)
            return response["Parameter"]["Value"].encode("ascii")
        except self.ssm.exceptions.ParameterNotFound as e:
            return None

    def delete(self, host):
        host = "root_ca" if host == "!!root_ca" else host
        name = f"{self.certificates_path}{host}"
        try:
            _ = self.ssm.delete_parameter(Name=name)
        except self.ssm.exceptions.ParameterNotFound:
            return

    def parameter_name(self, host):
        host = "root_ca" if host == "!!root_ca" else host
        return f"{self.certificates_path}{host}"
