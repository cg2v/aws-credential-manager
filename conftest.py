from dataclasses import dataclass
from time import sleep
from pytest import fixture
import boto3
from moto import mock_aws

from multicred.credentials  import Credentials, AwsRoleIdentity, AwsUserIdentity
from multicred.storage import Storage

@fixture
def role_identity():
    return AwsRoleIdentity(
        aws_identity='arn:aws:sts::123456789012:assumed-role/test_role/test_session',
        aws_userid='AROAEXAMPLE',
        aws_role_session_name='test_session')


@fixture
def user_identity():
    return AwsUserIdentity(
        aws_identity='arn:aws:iam::123456789012:user/test_user',
        aws_userid='AIDEXAMPLE')

@dataclass
class CredentialsWrapper:
    access_key_id: str
    secret_access_key: str
    session_token: str | None
    userid: str
    test_object: Credentials

def make_role_credentials():
    client = boto3.client('sts')
    response = client.assume_role(
        RoleArn='arn:aws:iam::123456789012:role/test_role',
        RoleSessionName='test_session',
    )
    credentials = Credentials(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'],
    )
    return CredentialsWrapper(
        access_key_id=response['Credentials']['AccessKeyId'],
        secret_access_key=response['Credentials']['SecretAccessKey'],
        session_token=response['Credentials']['SessionToken'],
        userid=response['AssumedRoleUser']['AssumedRoleId'].split(':')[0],
        test_object=credentials
    )

@fixture
def role_credentials():
    with mock_aws():
        yield make_role_credentials()

@fixture
def other_role_credentials():
    with mock_aws():
        yield make_role_credentials()

@fixture
def user_credentials():
    with mock_aws():
        iamclient = boto3.client('iam')
        user = iamclient.create_user(UserName='test_user')
        use_key = iamclient.create_access_key(UserName='test_user')
        credentials = Credentials(
            aws_access_key_id=use_key['AccessKey']['AccessKeyId'],
            aws_secret_access_key=use_key['AccessKey']['SecretAccessKey'],
        )
        yield CredentialsWrapper(
            access_key_id=use_key['AccessKey']['AccessKeyId'],
            secret_access_key=use_key['AccessKey']['SecretAccessKey'],
            session_token=None,
            userid=user['User']['UserId'],
            test_object=credentials
        )

@fixture
def unknown_credentials():
    return Credentials(
        aws_access_key_id='UNKNOWN',
        aws_secret_access_key='UNKNOWN',
    )

@fixture
def empty_storage():
    return Storage('sqlite:///:memory:')

@dataclass
class StorageWrapper:
    test_object: Storage
    credentials: CredentialsWrapper

@fixture
def role_creds_storage(role_credentials):
    storage = Storage('sqlite:///:memory:')
    storage.import_credentials(role_credentials.test_object, role_credentials.userid)
    return StorageWrapper(storage, role_credentials)

@fixture
def user_creds_storage(user_credentials):
    storage = Storage('sqlite:///:memory:')
    storage.import_credentials(user_credentials.test_object, user_credentials.userid)
    return StorageWrapper(storage, user_credentials)

@fixture
def multiple_creds_storage(role_credentials, user_credentials, other_role_credentials):
    storage = Storage('sqlite:///:memory:')
    storage.import_credentials(other_role_credentials.test_object, other_role_credentials.userid)
    sleep(5)
    storage.import_credentials(role_credentials.test_object, role_credentials.userid)
    storage.import_credentials(user_credentials.test_object, user_credentials.userid)
    return StorageWrapper(storage, role_credentials)