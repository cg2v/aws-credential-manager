import boto3

from . import interfaces
from . import credentials

class DBResolver(interfaces.Resolver):
    _storage: interfaces.Storage

    def __init__(self, storage: interfaces.Storage):
        self._storage = storage

    def get_credentials_by_arn(self, arn: str) -> credentials.Credentials | None:
        identity = self._storage.get_identity_by_arn(arn)
        if identity is None:
            return None
        rv = self._storage.get_identity_credentials(identity)
        if rv and rv.is_valid:
            return rv
        # XXX recurse
        return None

    def get_credentials_by_key(self, access_key: str) -> credentials.Credentials | None:
        return self._storage.get_credentials_by_key(access_key)

    def get_credentials_by_account_and_role_name(self, account_id: str, role_name: str) \
        -> credentials.Credentials | None:
        identity = self._storage.get_identity_by_account_and_role_name(account_id, role_name)
        if identity is None:
            return None
        rv = self._storage.get_identity_credentials(identity)
        if rv and rv.is_valid:
            return rv
        # XXX recurse
        return None
