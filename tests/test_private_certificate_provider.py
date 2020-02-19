import uuid
import boto3
from provider import handler
from test_private_root_certificate_provider import RootCertificateRequest


ssm = boto3.client("ssm")


def test_create():
    # create
    ca_name = "ca-%s" % uuid.uuid4()
    hostname = f"np17.{ca_name}"
    new_hostname = f"np17-2.{ca_name}"
    try:
        request = RootCertificateRequest("Create", ca_name)
        response = handler(request, {})
        assert response["Status"] == "SUCCESS", response["Reason"]

        request = CertificateRequest("Create", ca_name, hostname)
        response = handler(request, {})
        assert response["Data"]["CAName"] == ca_name
        assert response["Data"]["Hostname"] == hostname
        assert response["Status"] == "SUCCESS", response["Reason"]

        physical_resource_id = response.get("PhysicalResourceId")
        assert physical_resource_id

        request = CertificateRequest(
            "Update",
            ca_name,
            new_hostname,
            physical_resource_id=response["PhysicalResourceId"],
        )
        request["OldResourceProperties"] = {
            "CAName": ca_name,
            "Hostname": hostname,
        }
        update_response = handler(request, {})
        assert update_response["Status"] == "SUCCESS", update_response["Reason"]
        assert "PhysicalResourceId" in response
        assert update_response["Data"]["CAName"] == ca_name
        assert update_response["Data"]["Hostname"] == new_hostname
        new_physical_resource_id = update_response.get("PhysicalResourceId")
        assert new_physical_resource_id
        assert physical_resource_id != new_physical_resource_id
        r = ssm.get_parameter(Name=new_physical_resource_id, WithDecryption=True)

        failed_update_response = handler(request, {})
        assert failed_update_response["Status"] == "FAILED", failed_update_response[
            "Reason"
        ]
        assert "already exists" in failed_update_response["Reason"]

        for resource_id, name in [
            (physical_resource_id, hostname),
            (new_physical_resource_id, f"np17-2.{ca_name}"),
        ]:
            request = CertificateRequest(
                "Delete", ca_name, name, physical_resource_id=resource_id
            )
            response = handler(request, {})
            assert response["Status"] == "SUCCESS", response["Reason"]
            try:
                r = ssm.get_parameter(Name=resource_id)
                assert False, f"parameter {resource_id} still exists"
            except ssm.exceptions.ParameterNotFound:
                pass

    finally:
        pass
        handler(CertificateRequest("Delete", ca_name, hostname), {})
        handler(CertificateRequest("Delete", ca_name, new_hostname), {})
        handler(RootCertificateRequest("Delete", ca_name), {})

def test_refresh_on_update():
    # create
    ca_name = "ca-%s" % uuid.uuid4()
    hostname = "server.ca-%s" % uuid.uuid4()
    request = RootCertificateRequest("Create", ca_name)
    response = handler(request, {})
    assert response["Status"] == "SUCCESS", response["Reason"]
    hash = response["Data"]["Hash"]
    ca_physical_resource_id = response.get("PhysicalResourceId")


    request = CertificateRequest("Create", ca_name, hostname)
    response = handler(request, {})
    assert response["Data"]["CAName"] == ca_name
    assert response["Data"]["Hostname"] == hostname
    assert response["Status"] == "SUCCESS", response["Reason"]
    physical_resource_id = response.get("PhysicalResourceId")
    hash = response["Data"]["Hash"]

    request = CertificateRequest("Update", ca_name, hostname, physical_resource_id=physical_resource_id)
    response = handler(request, {})
    assert response["Status"] == "SUCCESS", response["Reason"]
    assert response.get("PhysicalResourceId") == physical_resource_id
    assert "PublicKeyPEM" in response["Data"]
    assert response["Data"]["Hash"] == hash

    request["ResourceProperties"]["RefreshOnUpdate"] = True
    response = handler(request, {})
    assert response["Status"] == "SUCCESS", response["Reason"]
    assert response.get("PhysicalResourceId") == physical_resource_id
    assert "PublicKeyPEM" in response["Data"]
    assert response["Data"]["Hash"] != hash


    request["RequestType"] = "Delete"
    response = handler(request, {})
    assert response["Status"] == "SUCCESS", response["Reason"]

    request = RootCertificateRequest(
        "Delete", ca_name, physical_resource_id=ca_physical_resource_id
    )
    response = handler(request, {})
    assert response["Status"] == "SUCCESS", response["Reason"]


class CertificateRequest(dict):
    def __init__(self, request_type, ca_name, hostname, physical_resource_id=None):
        request_id = "request-%s" % uuid.uuid4()
        self.update(
            {
                "RequestType": request_type,
                "ResponseURL": "https://httpbin.org/put",
                "StackId": "arn:aws:cloudformation:us-west-2:EXAMPLE/stack-name/guid",
                "RequestId": request_id,
                "ResourceType": "Custom::PrivateCertificate",
                "LogicalResourceId": "MyCustom",
                "ResourceProperties": {"CAName": ca_name, "Hostname": hostname},
            }
        )

        self["PhysicalResourceId"] = (
            physical_resource_id
            if physical_resource_id is not None
            else "initial-%s" % str(uuid.uuid4())
        )
