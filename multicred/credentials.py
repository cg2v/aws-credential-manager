"""Classes describing AWS credentials and the identity embedded in the credentials."""
from typing import TYPE_CHECKING
from collections.abc import Iterable
from dataclasses import dataclass, field
from configparser import ConfigParser, Error as ConfigParserError
import os
import botocore.exceptions
from boto3 import session

from .base_objects import IdentityKey, IdentityHandle, CredentialType, \
    MultiCredError
from .utils import parse_principal

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
    aws_identity: str = field(repr=False, compare=False)
    aws_userid : str
    _arn_components: list[str] = field(init=False, repr=False, compare=False)
    _resource_components: list[str] = field(
        init=False, repr=False, compare=False)
    _key: IdentityKey = field(init=False)
    cred_path: str = field(init=False, compare=False)

    def __post_init__(self):
        if not self.aws_identity.startswith('arn:aws:'):
            raise BadIdentityError('Invalid AWS identity')
        object.__setattr__(self, '_key',
                           parse_principal(self.aws_identity))
        elements = self.aws_identity.split(':')
        if len(elements) != 6:
            raise BadIdentityError('Invalid AWS identity')
        object.__setattr__(self, '_arn_components',  elements[4:])
        object.__setattr__(self, '_resource_components',
                           elements[5].split('/'))
        object.__setattr__(self, 'cred_path',
                           '/'.join(self._resource_components[1:]))

    @property
    def arn(self) -> str:
        return self.aws_identity

    @property
    def aws_account_id(self) -> str:
        return self._key.aws_account_id

    @property
    def cred_type(self) -> CredentialType:
        return self._key.cred_type

    @property
    def name(self) -> str:
        return self._key.name

    @property
    def key(self) -> IdentityKey:
        return self._key
    
    def put(self) -> ConfigParser:
        rv = ConfigParser()
        rv.add_section("identity")
        rv.set("identity", "arn", self.aws_identity)
        rv.set("identity", "userid", self.aws_userid)
        rv.set("identity", "cred_type", self.cred_type.value)
        return rv

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AwsIdentity):
            return self._key == other._key and \
                self.aws_userid == other.aws_userid
        arn = None
        if isinstance(other, IdentityHandle):
            arn = other.arn
        elif isinstance(other, str):
            arn = other
        if arn is None:
            return False
        try:
            key = parse_principal(arn)
        except ValueError:
            return False
        return self._key == key

    def __hash__(self) -> int:
        return hash(self._key)

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

    def put(self) -> ConfigParser:
        rv = super().put()
        rv.set("identity", "role_session_name", self.aws_role_session_name)
        return rv

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
    try:
        principal = parse_principal(aws_identity)
    except ValueError as e:
        raise BadIdentityError('Invalid AWS identity') from e
    if principal.cred_type == CredentialType.ROLE:
        return AwsRoleIdentity.from_caller_identity(identity)
    return AwsUserIdentity.from_caller_identity(identity)

def get_identity(config: ConfigParser) -> AwsIdentity:
    """Function to create an AwsIdentity object from a configparser.ConfigParser object."""
    try:
        arn = config.get("identity", "arn")
        cred_type = CredentialType(config.get("identity", "cred_type"))
        userid = config.get("identity", "userid")
        if cred_type == CredentialType.ROLE:
            role_session_name = config.get("identity", "role_session_name")
            return AwsRoleIdentity(arn, userid, role_session_name)
        return AwsIdentity(arn, userid)
    except (LookupError, ConfigParserError) as e:
        raise MissingCredentialsError('Missing identity data') from e

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

    def put(self) -> ConfigParser:
        rv = ConfigParser()
        rv.add_section("credentials")
        rv.set("credentials", "aws_access_key_id", self.aws_access_key_id)
        rv.set("credentials", "aws_secret_access_key", self.aws_secret_access_key)
        if self.aws_session_token is not None:
            rv.set("credentials", "aws_session_token", self.aws_session_token)
        return rv

    @classmethod
    def from_shared_credentials_file(cls, shared_credentials_file: os.PathLike | str | Iterable[str], profile_name='default',):
        config = ConfigParser()
        if isinstance(shared_credentials_file, (os.PathLike, str)):
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
