import boto3
import pytest

from agentleash.aws.client import OperationNotAllowed, ReadOnlySession


@pytest.fixture
def session():
    fake = boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        region_name="eu-west-2",
    )
    return ReadOnlySession(session=fake)


def test_call_refuses_write(session):
    with pytest.raises(OperationNotAllowed):
        session.call("iam", "CreateRole", RoleName="x", AssumeRolePolicyDocument="{}")


def test_paginate_refuses_write(session):
    with pytest.raises(OperationNotAllowed):
        list(session.paginate("iam", "ListRolePolicies"))


def test_direct_client_write_is_refused_before_any_request(session):
    # Bypassing ReadOnlySession.call must still be blocked by the botocore hook,
    # before a request is signed or sent (sockets are disabled in tests anyway).
    iam = session.client("iam")
    with pytest.raises(OperationNotAllowed):
        iam.delete_role(RoleName="anything")
