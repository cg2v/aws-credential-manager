"""Classes describing AWS credentials and the identity embedded in the credentials."""
from typing import TYPE_CHECKING
from collections.abc import Iterable
from dataclasses import dataclass, field
from configparser import ConfigParser
import botocore.exceptions
from boto3 import session

from .base_objects import IdentityHandle, CredentialType, MultiCredError

if TYPE_CHECKING:
    from mypy_boto3_sts.type_defs import GetCallerIdentityResponseTypeDef


class MissingCredentialsError(MultiCredError, KeyError):
    pass

class ExpiredCredentialsError(MultiCredError):
    pass

class WrongIdentityTypeError(MultiCredError, TypeError):
    pass

class BadIdentityError(MultiCredError, ValueError):
    pass


@dataclass(frozen=True, eq=False)
class AwsIdentity:
    aws_identity: str = field(repr=False)
    aws_userid : str
    _arn_components: list[str] = field(init=False, repr=False, compare=False)
    _resource_components: list[str] = field(
        init=False, repr=False, compare=False)
    aws_account_id: str = field(init=False, compare=False)
    cred_type: CredentialType = field(init=False, compare=False)
    cred_path: str = field(init=False, compare=False)

    def __post_init__(self):
        if not self.aws_identity.startswith('arn:aws:'):
            raise BadIdentityError('Invalid AWS identity')
        elements = self.aws_identity.split(':')
        if len(elements) != 6:
            raise BadIdentityError('Invalid AWS identity')
        object.__setattr__(self, '_arn_components',  elements[4:])
        object.__setattr__(self, '_resource_components',
                           elements[5].split('/'))
        object.__setattr__(self, 'aws_account_id', elements[4])
        object.__setattr__(self, 'cred_type', CredentialType[self._resource_components[0].upper().replace('-', '_')])
        object.__setattr__(self, 'cred_path',
                           '/'.join(self._resource_components[1:]))

    @property
    def arn(self) -> str:
        return self.aws_identity

    @property
    def name(self) -> str:
        if len(self._resource_components) == 2 or (
                len(self._resource_components) == 3 and self.cred_type == CredentialType.ROLE
        ):
            return self._resource_components[1]
        raise WrongIdentityTypeError('This identity does not have a simple name')

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AwsIdentity):
            return self.aws_identity == other.aws_identity and \
                self.aws_userid == other.aws_userid
        if isinstance(other, str):
            return self.aws_identity == other
        if isinstance(other, IdentityHandle):
            return self.aws_identity == other.arn
        return False

    def __hash__(self) -> int:
        return hash(self.aws_identity)

@dataclass(frozen=True, eq=False)
class AwsRoleIdentity(AwsIdentity):
    """Class to represent the identity of the AWS role assumed by the credentials."""
    aws_role_name: str = field(init=False, compare=False)
    aws_role_session_name: str

    def __post_init__(self):
        super().__post_init__()
        if self.cred_type != CredentialType.ROLE:
            raise WrongIdentityTypeError('Invalid AWS assumed role identity')
        if self._resource_components[2] != self.aws_role_session_name:
            raise BadIdentityError('Inconsistent AWS assumed role identity')
        object.__setattr__(self, 'aws_role_name', self._resource_components[1])

    @classmethod
    def from_caller_identity(cls, identity: 'GetCallerIdentityResponseTypeDef'):
        aws_identity = identity['Arn']
        userid = identity['UserId']
        aws_role_id = userid.split(':')[0]
        aws_role_session_name = userid.split(':')[1]

        return cls(aws_identity=aws_identity, aws_userid=aws_role_id, aws_role_session_name=aws_role_session_name)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AwsRoleIdentity):
            return self.aws_identity == other.aws_identity and \
                self.aws_userid == other.aws_userid and \
                self.aws_role_session_name == other.aws_role_session_name
        return super().__eq__(other)

    def __hash__(self) -> int:
        return super().__hash__()

@dataclass(frozen=True)
class AwsUserIdentity(AwsIdentity):
    """Class to represent the identity of the AWS user represented by the credentials."""
    aws_user_name: str = field(init=False, compare=False)

    def __post_init__(self):
        super().__post_init__()
        if self.cred_type != CredentialType.USER:
            raise WrongIdentityTypeError('Invalid AWS identity')
        object.__setattr__(self, 'aws_user_name', self._resource_components[1])

    @classmethod
    def from_caller_identity(cls, identity: 'GetCallerIdentityResponseTypeDef'):
        aws_identity = identity['Arn']
        userid = identity['UserId']
        aws_user_id = userid.split(':')[0]

        return cls(aws_identity=aws_identity, aws_userid=aws_user_id)

@dataclass(frozen=True)
class AwsUnknownIdentity(AwsIdentity):
    """Class to represent an unknown AWS identity."""

    @property
    def name(self) -> str:
        return 'UNKNOWN'

def to_role_identity(aws_identity: AwsIdentity) -> AwsRoleIdentity:
    """Function to convert an AwsIdentity object to an AwsRoleIdentity object."""
    if aws_identity.cred_type == CredentialType.ROLE:
        if isinstance(aws_identity, AwsRoleIdentity):
            return aws_identity
        role_session_name = aws_identity.cred_path.split('/')[-1]
        return AwsRoleIdentity(
            aws_identity=aws_identity.aws_identity,
            aws_userid=aws_identity.aws_userid,
            aws_role_session_name=role_session_name)
    raise WrongIdentityTypeError('Not a role identity')

def import_identity(identity: 'GetCallerIdentityResponseTypeDef') -> AwsIdentity:
    """Factory function to create an AwsIdentity object from a boto3 GetCallerIdentity response."""
    aws_identity = identity['Arn']
    arn_components = aws_identity.split(':')
    if arn_components[5].startswith('assumed-role'):
        return AwsRoleIdentity.from_caller_identity(identity)
    return AwsUserIdentity.from_caller_identity(identity)

UNKNOWN_IDENTITY = AwsUnknownIdentity(aws_identity='arn:aws:::UNKNOWN:unknown',
                                      aws_userid='UNKNOWN')
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
