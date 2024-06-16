from dataclasses import dataclass
from typing import Tuple
import boto3

from . import interfaces
from . import credentials

@dataclass(frozen=True)
class ResolverState:
    identity: interfaces.IdentityHandle
    role_name: str

class DBResolver(interfaces.Resolver):
    _storage: interfaces.Storage

    def __init__(self, storage: interfaces.Storage):
        self._storage = storage

    def _build_path(self, identity: interfaces.IdentityHandle) -> Tuple[list[ResolverState], credentials.Credentials | None]:
        rv = []
        while True:
            creds = self._storage.get_identity_credentials(identity)
            if creds is not None:
                break
            parent, role_name = self._storage.get_parent_identity(identity)
            if parent is None:
                break
            assert role_name is not None
            rv.append(ResolverState(identity=identity, role_name=role_name))
            identity = parent
        return rv, creds

    def _get_credentials_from_path(self, creds: credentials.Credentials, path: list[ResolverState]) -> credentials.Credentials | None:
        while path:
            item = path.pop()
            role_name = item.role_name
            identity = item.identity
            client = boto3.client('sts', **creds.get_boto3_credentials())
            response = client.assume_role(
                RoleArn=role_name,
                RoleSessionName=identity.name)
            creds = credentials.Credentials(
                aws_access_key_id=response['Credentials']['AccessKeyId'],
                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                aws_session_token=response['Credentials']['SessionToken'])
            self._storage.import_credentials(creds)
        return creds

    def _get_credentials_for_identity(self, identity: interfaces.IdentityHandle) -> credentials.Credentials | None:
        rv = self._storage.get_identity_credentials(identity)
        if rv and rv.is_valid:
            return rv
        path, creds = self._build_path(identity)
        if creds is None:
            return None
        return self._get_credentials_from_path(creds, path)

    def get_credentials_by_arn(self, arn: str) -> credentials.Credentials | None:
        identity = self._storage.get_identity_by_arn(arn)
        if identity is None:
            return None
        return self._get_credentials_for_identity(identity)

    def get_credentials_by_key(self, access_key: str) -> credentials.Credentials | None:
        return self._storage.get_credentials_by_key(access_key)

    def get_credentials_by_account_and_role_name(self, account_id: str, role_name: str) \
        -> credentials.Credentials | None:
        identity = self._storage.get_identity_by_account_and_role_name(account_id, role_name)
        if identity is None:
            return None
        return self._get_credentials_for_identity(identity)
