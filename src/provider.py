import os
import logging
import cfn_private_certificate_provider
import cfn_private_root_certificate_provider

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))


def handler(request, context):
    logging.getLogger().setLevel(os.getenv("LOG_LEVEL", "INFO"))
    if request["ResourceType"] == "Custom::PrivateRootCertificate":
        return cfn_private_root_certificate_provider.handler(request, context)
    else:
        return cfn_private_certificate_provider.handler(request, context)
