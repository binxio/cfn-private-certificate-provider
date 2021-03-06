import uuid

import boto3

from provider import handler
from cfn_private_root_certificate_provider import find_all_root_cas

ssm = boto3.client("ssm")


def test_crud():
    # create
    ca_name = "ca-%s" % uuid.uuid4()
    try:
        request = RootCertificateRequest("Create", ca_name)
        response = handler(request, {})
        assert response["Status"] == "SUCCESS", response["Reason"]
        assert "PhysicalResourceId" in response
        assert "PublicCertPEM" in response["Data"]
        assert "Hash" in response["Data"]
        assert response["Data"]["CAName"] == ca_name
        hash = response["Data"]["Hash"]
        physical_resource_id = response.get("PhysicalResourceId")
        r = ssm.get_parameter(Name=response["PhysicalResourceId"], WithDecryption=True)

        request = RootCertificateRequest(
            "Update", ca_name, physical_resource_id=physical_resource_id
        )
        response = handler(request, {})
        assert response["Status"] == "SUCCESS", response["Reason"]
        assert "PhysicalResourceId" in response
        assert "PublicCertPEM" in response["Data"]
        assert response["Data"]["Hash"] == hash
        r = ssm.get_parameter(Name=response["PhysicalResourceId"], WithDecryption=True)

        request = RootCertificateRequest(
            "Delete", ca_name, physical_resource_id=physical_resource_id
        )
        response = handler(request, {})
        assert response["Status"] == "SUCCESS", response["Reason"]
        try:
            r = ssm.get_parameter(
                Name=response["PhysicalResourceId"], WithDecryption=True
            )
            assert False, f"root ca parameter store {physical_resource_id} still exists"
        except ssm.exceptions.ParameterNotFound:
            pass
    finally:
        pass
        handler(RootCertificateRequest("Delete", ca_name), {})


def test_rename():
    # create
    ca_name = "ca-%s" % uuid.uuid4()
    new_ca_name = "new-ca-%s" % uuid.uuid4()
    request = RootCertificateRequest("Create", ca_name)
    response = handler(request, {})
    assert response["Status"] == "SUCCESS", response["Reason"]
    assert "PhysicalResourceId" in response
    assert "PublicCertPEM" in response["Data"]
    assert "Hash" in response["Data"]
    hash = response["Data"]["Hash"]
    physical_resource_id = response.get("PhysicalResourceId")
    r = ssm.get_parameter(Name=physical_resource_id, WithDecryption=True)

    request = RootCertificateRequest(
        "Update", new_ca_name, physical_resource_id=physical_resource_id
    )
    request["OldResourceProperties"] = {"CAName": ca_name}
    response = handler(request, {})
    assert response["Status"] == "SUCCESS", response["Reason"]
    assert response.get("PhysicalResourceId") != physical_resource_id
    assert "PublicCertPEM" in response["Data"]
    assert response["Data"]["Hash"] != hash
    assert response["Data"]["CAName"] == new_ca_name
    new_physical_resource_id = response["PhysicalResourceId"]
    r = ssm.get_parameter(Name=new_physical_resource_id, WithDecryption=True)
    failed_update_response = handler(request, {})
    assert failed_update_response["Status"] == "FAILED", response["Reason"]
    assert "already exists" in failed_update_response["Reason"]

    for resource_id, name in [
        (physical_resource_id, ca_name),
        (new_physical_resource_id, new_ca_name),
    ]:
        request = RootCertificateRequest(
            "Delete", name, physical_resource_id=resource_id
        )
        response = handler(request, {})
        assert response["Status"] == "SUCCESS", response["Reason"]
        try:
            r = ssm.get_parameter(Name=resource_id)
            assert False, f"root ca parameter store {physical_resource_id} still exists"
        except ssm.exceptions.ParameterNotFound:
            pass


def test_refresh_on_update():
    # create
    ca_name = "ca-%s" % uuid.uuid4()
    request = RootCertificateRequest("Create", ca_name)
    response = handler(request, {})
    assert response["Status"] == "SUCCESS", response["Reason"]
    hash = response["Data"]["Hash"]
    physical_resource_id = response.get("PhysicalResourceId")

    request = RootCertificateRequest(
        "Update", ca_name, physical_resource_id=physical_resource_id
    )
    response = handler(request, {})
    assert response["Status"] == "SUCCESS", response["Reason"]
    assert response.get("PhysicalResourceId") == physical_resource_id
    assert "PublicCertPEM" in response["Data"]
    assert response["Data"]["Hash"] == hash

    request["ResourceProperties"]["RefreshOnUpdate"] = True
    response = handler(request, {})
    assert response["Status"] == "SUCCESS", response["Reason"]
    assert response.get("PhysicalResourceId") == physical_resource_id
    assert "PublicCertPEM" in response["Data"]
    assert response["Data"]["Hash"] != hash

    request = RootCertificateRequest(
        "Delete", ca_name, physical_resource_id=physical_resource_id
    )
    response = handler(request, {})
    assert response["Status"] == "SUCCESS", response["Reason"]


class RootCertificateRequest(dict):
    def __init__(self, request_type, ca_name, physical_resource_id=None):
        request_id = "request-%s" % uuid.uuid4()
        self.update(
            {
                "RequestType": request_type,
                "ResponseURL": "https://httpbin.org/put",
                "StackId": "arn:aws:cloudformation:us-west-2:EXAMPLE/stack-name/guid",
                "RequestId": request_id,
                "ResourceType": "Custom::PrivateRootCertificate",
                "LogicalResourceId": "MyCustom",
                "ResourceProperties": {"CAName": ca_name},
            }
        )

        self["PhysicalResourceId"] = (
            physical_resource_id
            if physical_resource_id is not None
            else "initial-%s" % str(uuid.uuid4())
        )


def test_find_all_root_cas():
    base_name = "ca-%s" % uuid.uuid4()
    ca_names = set([f"{base_name}-{x}" for x in range(0, 4)])

    try:
        for ca_name in ca_names:
            request = RootCertificateRequest("Create", ca_name)
            response = handler(request, {})
            assert response["Status"] == "SUCCESS", response["Reason"]

        root_cas = find_all_root_cas()

        assert ca_names == root_cas.intersection(ca_names)
    finally:
        for ca_name in ca_names:
            request = RootCertificateRequest(
                "Delete",
                ca_name,
                physical_resource_id="arn:aws:ssm:eu-central-1:123456789012:parameter/x",
            )
            response = handler(request, {})
            print(response["Reason"])
