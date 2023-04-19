from cfn_private_certificate_provider import private_root_certificate
from cfn_private_certificate_provider import private_certificate

def handler(request, context):
    if request["ResourceType"] == 'Custom::PrivateRootCertificate':
        return private_root_certificate.handler(request, context)
    else:
        return private_certificate.handler(request, context)
