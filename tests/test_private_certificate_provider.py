import uuid
from provider import handler


def test_create():
    # create
    ca_name = 'ca-%s' % uuid.uuid4()
    try:
        request = RootCertificateRequest('Create', ca_name)
        response = handler(request, {})
        assert response['Status'] == 'SUCCESS', response['Reason']
        assert 'PhysicalResourceId' in response

        request = CertificateRequest('Create', ca_name, f"np17.{ca_name}")
        response = handler(request, {})
        assert response['Status'] == 'SUCCESS', response['Reason']
        assert 'PhysicalResourceId' in response
    finally:
        pass
        handler(CertificateRequest("Delete", ca_name, f"np17.{ca_name}"), {})
        handler(RootCertificateRequest("Delete", ca_name), {})


class RootCertificateRequest(dict):

    def __init__(self, request_type, ca_name, physical_resource_id=None):
        request_id = 'request-%s' % uuid.uuid4()
        self.update({
            'RequestType': request_type,
            'ResponseURL': 'https://httpbin.org/put',
            'StackId': 'arn:aws:cloudformation:us-west-2:EXAMPLE/stack-name/guid',
            'RequestId': request_id,
            'ResourceType': 'Custom::PrivateRootCertificate',
            'LogicalResourceId': 'MyCustom',
            'ResourceProperties': {
                'CAName': ca_name,
            }})

        self['PhysicalResourceId'] = physical_resource_id if physical_resource_id is not None else 'initial-%s' % str(uuid.uuid4())

class CertificateRequest(dict):

    def __init__(self, request_type, ca_name, hostname, physical_resource_id=None):
        request_id = 'request-%s' % uuid.uuid4()
        self.update({
            'RequestType': request_type,
            'ResponseURL': 'https://httpbin.org/put',
            'StackId': 'arn:aws:cloudformation:us-west-2:EXAMPLE/stack-name/guid',
            'RequestId': request_id,
            'ResourceType': 'Custom::PrivateCertificate',
            'LogicalResourceId': 'MyCustom',
            'ResourceProperties': {
                'CAName': ca_name,
                'Hostname': hostname
            }})

        self['PhysicalResourceId'] = physical_resource_id if physical_resource_id is not None else 'initial-%s' % str(uuid.uuid4())
