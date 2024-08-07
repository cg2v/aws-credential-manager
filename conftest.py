from dataclasses import dataclass
from time import sleep
import json
from pytest import fixture
import boto3
from moto import mock_aws

from multicred.credentials  import CredentialType, Credentials, AwsRoleIdentity, AwsUserIdentity
from multicred.dbstorage import DBStorage
from multicred.resolver import StorageBasedResolver
from multicred.interfaces import Storage, Resolver

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

@dataclass(frozen=True)
class TestIdentityHandle:
    @property
    def aws_account_id(self) -> str:
        return '123456789012'
    @property
    def arn(self) -> str:
        return 'arn:aws:sts::123456789012:assumed-role/test_role/test_session'
    @property
    def cred_type(self) -> CredentialType:
        return CredentialType.ROLE
    @property
    def name(self) -> str:
        return 'test_role'
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return other.__eq__(self)
        return self.arn == other.arn
    def __hash__(self) -> int:
        return hash(self.arn)

@fixture
def test_identity_handle():
    return TestIdentityHandle()

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
    return DBStorage('sqlite:///:memory:')

@fixture
def empty_resolver(empty_storage):
    return StorageBasedResolver(empty_storage)

@dataclass
class StorageWrapper:
    test_object: Storage
    credentials: CredentialsWrapper

@fixture
def role_creds_storage(role_credentials):
    storage = DBStorage('sqlite:///:memory:')
    storage.import_credentials(role_credentials.test_object)
    return StorageWrapper(storage, role_credentials)

@fixture
def user_creds_storage(user_credentials):
    storage = DBStorage('sqlite:///:memory:')
    storage.import_credentials(user_credentials.test_object)
    return StorageWrapper(storage, user_credentials)

@fixture
def multiple_creds_storage(role_credentials, user_credentials, other_role_credentials):
    storage = DBStorage('sqlite:///:memory:')
    storage.import_credentials(other_role_credentials.test_object)
    sleep(5)
    storage.import_credentials(role_credentials.test_object)
    storage.import_credentials(user_credentials.test_object)
    return StorageWrapper(storage, role_credentials)

@dataclass
class ResolverWrapper:
    test_object: Resolver
    credentials: CredentialsWrapper

@fixture
def role_creds_resolver(role_creds_storage):
    resolver = StorageBasedResolver(role_creds_storage.test_object)
    return ResolverWrapper(resolver, role_creds_storage.credentials)

@fixture
def user_creds_resolver(user_creds_storage):
    resolver = StorageBasedResolver(user_creds_storage.test_object)
    return ResolverWrapper(resolver, user_creds_storage.credentials)

@fixture
def multiple_creds_resolver(multiple_creds_storage):
    resolver = StorageBasedResolver(multiple_creds_storage.test_object)
    return ResolverWrapper(resolver, multiple_creds_storage.credentials)

@fixture
def user_may_assume_role(user_credentials, role_credentials):
    with mock_aws():
        iamclient = boto3.client('iam')
        iamclient.create_policy(
            PolicyName='test_policy',
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17", 
                    "Statement": [
                        {
                            "Effect": "Allow", 
                            "Action": "sts:AssumeRole", 
                            "Resource": role_credentials.test_object.aws_identity.aws_identity,
                        }
                    ]
                }
            )
        )
        iamclient.attach_user_policy(
            UserName=user_credentials.test_object.aws_identity.aws_user_name,
            PolicyArn='arn:aws:iam::123456789012:policy/test_policy'
        )
        yield

@dataclass
class DerivedCredsStorageWrapper:
    test_object: Storage
    user_creds: CredentialsWrapper
    role_creds: CredentialsWrapper
    role_arn: str

@fixture
def derived_creds_storage(user_credentials, role_credentials, user_may_assume_role):
    storage = DBStorage('sqlite:///:memory:')
    storage.import_credentials(user_credentials.test_object)
    storage.import_credentials(role_credentials.test_object)
    role_arn = 'arn:aws:iam::123456789012:role/test_role'
    storage.construct_identity_relationship(role_credentials.test_object,
                                            user_credentials.test_object, role_arn)
    return DerivedCredsStorageWrapper(storage, user_credentials, role_credentials, role_arn)

@dataclass
class DerivedCredsResolverWrapper:
    test_object: Resolver
    storage: StorageWrapper
    user_creds: CredentialsWrapper
    role_creds: CredentialsWrapper
    role_arn: str

@fixture
def derived_creds_resolver(derived_creds_storage):
    return DerivedCredsResolverWrapper(
        StorageBasedResolver(derived_creds_storage.test_object),
        derived_creds_storage,
        derived_creds_storage.user_creds,
        derived_creds_storage.role_creds,
        derived_creds_storage.role_arn)
