"""Classes describing AWS credentials and the identity embedded in the credentials."""
from typing import TYPE_CHECKING
from dataclasses import dataclass, field
import datetime
from configparser import ConfigParser
from botocore import exceptions
from boto3 import session

if TYPE_CHECKING:
    from mypy_boto3_sts.type_defs import GetCallerIdentityResponseTypeDef


class MultiCredError(Exception):
    pass


class MissingCredentialsError(MultiCredError):
    pass


class ExpiredCredentialsError(MultiCredError):
    pass


@dataclass
class AwsIdentity:
    """Class to represent the identity of the AWS role assumed by the credentials."""
    aws_identity: str
    aws_account_id: str = field(init=False, hash=False, compare=False)
    aws_role_id: str
    aws_role_name: str = field(init=False, hash=False, compare=False)
    aws_role_session_name: str | None = field(
        init=False, hash=False, compare=False)

    def __post_init__(self):
        self.aws_account_id = self.aws_identity.split(':')[4]
        self.aws_role_name = self.aws_identity.split('/')[-1]
        self.aws_role_session_name = self.aws_identity.split(':')[1]

    @classmethod
    def from_caller_identity(cls, identity: 'GetCallerIdentityResponseTypeDef'):
        aws_identity = identity['Arn']
        userid = identity['UserId']
        aws_role_id = userid.split(':')[0]

        return cls(aws_identity=aws_identity, aws_role_id=aws_role_id)


@dataclass
class Credentials:
    """Class to represent AWS credentials and the identity of the role assumed by the credentials."""
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_session_token: str | None = None
    aws_expiration: datetime.datetime = field(
        init=False, hash=False, compare=False)
    aws_identity: AwsIdentity | None = field(
        init=False, hash=False, compare=False)

    def __post_init__(self):
        s = session.Session()
        client = s.client('sts', aws_access_key_id=self.aws_access_key_id,
                          aws_secret_access_key=self.aws_secret_access_key,
                          aws_session_token=self.aws_session_token)
        identity = client.get_caller_identity()
        self.aws_identity = AwsIdentity.from_caller_identity(identity)

    def is_expired(self):
        return self.aws_expiration is not None and self.aws_expiration < datetime.datetime.now()

    def is_valid(self):
        return self.aws_access_key_id is not None and self.aws_secret_access_key is not None

    def get_boto3_credentials(self):
        if not self.is_valid():
            raise exceptions.PartialCredentialsError(provider='multicred')
        return {
            'aws_access_key_id': self.aws_access_key_id,
            'aws_secret_access_key': self.aws_secret_access_key,
            'aws_session_token': self.aws_session_token,
        }

    @classmethod
    def from_shared_credentials_file(cls, shared_credentials_file, profile_name='default',):
        config = ConfigParser()
        config.read(shared_credentials_file)
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
