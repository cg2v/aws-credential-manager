"""Classes describing AWS credentials and the identity embedded in the credentials."""
from typing import TYPE_CHECKING
from collections.abc import Iterable
from dataclasses import dataclass, field
import datetime
from configparser import ConfigParser
import botocore.exceptions
from boto3 import session

if TYPE_CHECKING:
    from mypy_boto3_sts.type_defs import GetCallerIdentityResponseTypeDef


class MultiCredError(Exception):
    pass


class MissingCredentialsError(MultiCredError):
    pass


class ExpiredCredentialsError(MultiCredError):
    pass


@dataclass(frozen=True)
class AwsIdentity:
    aws_identity: str = field(repr=False)
    aws_userid : str
    _arn_components: list[str] = field(init=False, repr=False, compare=False)
    _resource_components: list[str] = field(
        init=False, repr=False, compare=False)
    aws_account_id: str = field(init=False, compare=False)
    cred_type: str = field(init=False, compare=False)
    cred_path: str = field(init=False, compare=False)

    def __post_init__(self):
        if not self.aws_identity.startswith('arn:aws:'):
            raise ValueError('Invalid AWS identity')
        elements = self.aws_identity.split(':')
        if len(elements) != 6:
            raise ValueError('Invalid AWS identity')
        object.__setattr__(self, '_arn_components',  elements[4:])
        object.__setattr__(self, '_resource_components',
                           elements[5].split('/'))
        object.__setattr__(self, 'aws_account_id', elements[4])
        object.__setattr__(self, 'cred_type', self._resource_components[0])
        object.__setattr__(self, 'cred_path',
                           '/'.join(self._resource_components[1:]))


@dataclass(frozen=True)
class AwsRoleIdentity(AwsIdentity):
    """Class to represent the identity of the AWS role assumed by the credentials."""
    aws_role_name: str = field(init=False, compare=False)
    aws_role_session_name: str

    def __post_init__(self):
        super().__post_init__()
        if ':sts:' not in self.aws_identity:
            raise ValueError('Invalid AWS assumed role identity')
        if self.cred_type != 'assumed-role':
            raise ValueError('Invalid AWS assumed role identity')
        if self._resource_components[2] != self.aws_role_session_name:
            raise ValueError('Inconsistent AWS assumed role identity')
        object.__setattr__(self, 'aws_role_name', self._resource_components[1])

    @classmethod
    def from_caller_identity(cls, identity: 'GetCallerIdentityResponseTypeDef'):
        aws_identity = identity['Arn']
        userid = identity['UserId']
        aws_role_id = userid.split(':')[0]
        aws_role_session_name = userid.split(':')[1]

        return cls(aws_identity=aws_identity, aws_userid=aws_role_id, aws_role_session_name=aws_role_session_name)


@dataclass(frozen=True)
class AwsUserIdentity(AwsIdentity):
    """Class to represent the identity of the AWS user represented by the credentials."""
    aws_user_name: str = field(init=False, compare=False)

    def __post_init__(self):
        super().__post_init__()
        if ':iam:' not in self.aws_identity:
            raise ValueError('Invalid AWS user identity')
        if self.cred_type != 'user':
            raise ValueError('Invalid AWS identity')
        object.__setattr__(self, 'aws_user_name', self._resource_components[1])

    @classmethod
    def from_caller_identity(cls, identity: 'GetCallerIdentityResponseTypeDef'):
        aws_identity = identity['Arn']
        userid = identity['UserId']
        aws_user_id = userid.split(':')[0]

        return cls(aws_identity=aws_identity, aws_userid=aws_user_id)


def import_identity(identity: 'GetCallerIdentityResponseTypeDef') -> AwsIdentity:
    """Factory function to create an AwsIdentity object from a boto3 GetCallerIdentity response."""
    aws_identity = identity['Arn']
    if aws_identity.startswith('arn:aws:sts::'):
        return AwsRoleIdentity.from_caller_identity(identity)
    return AwsUserIdentity.from_caller_identity(identity)

UNKNOWN_IDENTITY = AwsIdentity(aws_identity='arn:aws:::UNKNOWN:unknown', aws_userid='UNKNOWN')
@dataclass
class Credentials:
    """Class to represent AWS credentials and the identity of the role represented by the credentials."""
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_session_token: str | None = None
    aws_identity: AwsIdentity = field(
        init=False, hash=False, compare=False)
    is_expired: bool = field(init=False, hash=False, compare=False)
    is_valid: bool = field(init=False, hash=False, compare=False)
    def __post_init__(self):
        self.is_expired = False
        self.is_valid = False
        s = session.Session()
        try:
            client = s.client('sts', aws_access_key_id=self.aws_access_key_id,
                              aws_secret_access_key=self.aws_secret_access_key,
                              aws_session_token=self.aws_session_token)
            identity = client.get_caller_identity()
        except botocore.exceptions.ClientError as e:
            self.aws_identity = UNKNOWN_IDENTITY
            if e.response['Error']['Code'] == 'ExpiredToken': # type: ignore
                self.is_expired = True
        else:
            self.is_valid = True
            self.aws_identity = import_identity(identity)


    def get_boto3_credentials(self):
        return {
            'aws_access_key_id': self.aws_access_key_id,
            'aws_secret_access_key': self.aws_secret_access_key,
            'aws_session_token': self.aws_session_token,
        }

    @classmethod
    def from_shared_credentials_file(cls, shared_credentials_file: str | Iterable[str], profile_name='default',):
        config = ConfigParser()
        if isinstance(shared_credentials_file, str):
            config.read(shared_credentials_file)
        else:
            config.read_file(shared_credentials_file)
        if not config.has_section(profile_name):
            raise MissingCredentialsError(
                f"Profile {profile_name} not found in {shared_credentials_file}")
        access_key_id = config.get(
            profile_name, 'aws_access_key_id', fallback=None)
        secret_access_key = config.get(
            profile_name, 'aws_secret_access_key', fallback=None)
        session_token = config.get(
            profile_name, 'aws_session_token', fallback=None)
        if access_key_id is None or secret_access_key is None:
            raise MissingCredentialsError(
                f"Access key or secret key not found in {shared_credentials_file}")
        return cls(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            aws_session_token=session_token)
