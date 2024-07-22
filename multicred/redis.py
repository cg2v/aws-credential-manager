from typing import Tuple
from collections.abc import Iterator
from io import StringIO
from datetime import datetime
from configparser import ConfigParser
import redis

from . import credentials
from .base_objects import IdentityHandle, MultiCredError,\
      MultiCredBadRequest, MultiCredLinkError
from .interfaces import Statistics, CredentialInfo
from .utils import parse_principal

class RedisStorageError(MultiCredError):
    pass

class RedisStorage:
    _redis: 'redis.Redis[str]'
    _prefix: str
    def __init__(self, url: str, prefix='aws-cred-cache', /, reset = False):
        self._redis = redis.Redis.from_url(url, decode_responses=True)
        if reset:
            self._redis.flushdb()
        self._prefix = prefix
    def _get_handle_from_key(self, key: str) -> IdentityHandle | None:
        data = self._redis.get(key)
        if not data:
            return None
        if not isinstance(data, str):
            raise RedisStorageError(f'Invalid data type for key {key}')
        config = ConfigParser()
        config.read_string(data)
        return credentials.get_identity(config)

    def _get_key_from_handle(self, handle: IdentityHandle, /, namespace='identity') -> str:
        return f'{self._prefix}:{namespace}:{handle.cred_type.value}:'\
            f'{handle.aws_account_id}:{handle.name}'

    def get_identity_by_arn(self, arn: str) -> IdentityHandle | None:
        try:
            key = parse_principal(arn)
        except ValueError:
            return None
        key = f'{self._prefix}:identity:{key.cred_type.value}:{key.aws_account_id}:{key.name}'
        return self._get_handle_from_key(key)

    def get_identity_by_account_and_role_name(self, account_id: str, role_name: str) \
        -> IdentityHandle | None:
        key = f'{self._prefix}:identity:role:{account_id}:{role_name}'
        return self._get_handle_from_key(key)

    def get_parent_identity(self, identity: IdentityHandle) \
        -> Tuple[IdentityHandle, str] | tuple[None, None]:
        key = self._get_key_from_handle(identity, namespace='parent')
        data = self._redis.get(key)
        if not data:
            return None, None
        config = ConfigParser()
        config.read_string(data)
        if 'parent' not in config:
            raise RedisStorageError(f'Invalid parent data found for key {key}: {data}')
        parentkey = config.get('parent', 'parent_key')
        role_name = config.get('parent', 'role_name')
        rv = self._get_handle_from_key(parentkey)
        if rv is None:
            raise RedisStorageError(f'Invalid parent key found for {identity}: {parentkey}')
        return rv, role_name

    def construct_identity_relationship(self, creds: credentials.Credentials,
                                  parent_creds: credentials.Credentials,
                                  role_arn: str) \
                                    -> None:
        if creds.aws_identity.cred_type != credentials.CredentialType.ROLE:
            raise MultiCredLinkError("Can only construct relationships for roles")
        key = self._get_key_from_handle(creds.aws_identity, namespace='parent')
        if self._redis.exists(key):
            raise MultiCredLinkError(f'Parent relationship already exists for {creds.aws_identity}')
        config = ConfigParser()
        config.add_section('parent')
        config.set('parent', 'parent_key', self._get_key_from_handle(parent_creds.aws_identity))
        config.set('parent', 'role_name', role_arn)
        with StringIO() as buf:
            config.write(buf)
            data = buf.getvalue()
        self._redis.set(key, data, nx=True)
        parent_child_key = self._get_key_from_handle(parent_creds.aws_identity, namespace='child')
        self._redis.sadd(parent_child_key, self._get_key_from_handle(creds.aws_identity))

    def remove_identity_relationship(self, identity: IdentityHandle) -> None:
        identity_key = self._get_key_from_handle(identity)
        children_key = self._get_key_from_handle(identity, namespace='child')
        count = self._redis.scard(children_key)
        if count > 0:
            raise MultiCredLinkError(f'Cannot remove identity with {count} children')
        object_parent_key = self._get_key_from_handle(identity, namespace='parent')
        data = self._redis.get(object_parent_key)
        if not data:
            return
        config = ConfigParser()
        config.read_string(data)
        if 'parent' not in config:
            raise RedisStorageError(f'Invalid parent data found for key {object_parent_key}: {data}')
        parent_id_key = config.get('parent', 'parent_key')
        parent_child_key = parent_id_key.replace('identity', 'child')
        self._redis.srem(parent_child_key, identity_key)
        self._redis.delete(object_parent_key)

    def import_credentials(self, creds: credentials.Credentials) -> None:
        key = self._get_key_from_handle(creds.aws_identity)
        if not self._redis.exists(key):
            with StringIO() as buf:
                creds.aws_identity.put().write(buf)
                data = buf.getvalue()
            self._redis.set(key, data)
        account_key = f'{self._prefix}:account:{creds.aws_identity.aws_account_id}'
        self._redis.sadd(account_key, key)
        all_identities_key = f'{self._prefix}:identities'
        self._redis.sadd(all_identities_key, key)
        credkey = f'{self._prefix}:credentials:{creds.aws_access_key_id}'
        if self._redis.exists(credkey):
            raise MultiCredBadRequest(f'Credentials already exist for {creds.aws_access_key_id}')
        with StringIO() as buf:
            creds.put().write(buf)
            data = buf.getvalue()
        self._redis.set(credkey, data)
        id_creds_key = self._get_key_from_handle(creds.aws_identity, namespace='idcredentials')
        self._redis.zadd(id_creds_key, {creds.aws_access_key_id: datetime.now().timestamp()})
        cred_id_key = f'{self._prefix}:credentials:{creds.aws_access_key_id}:identity'
        self._redis.set(cred_id_key, key)

    def get_identity_credentials(self, identity: IdentityHandle) \
        -> credentials.Credentials | None:
        id_creds_key = self._get_key_from_handle(identity, namespace='idcredentials')
        keys = self._redis.zrevrange(id_creds_key, 0, 0)
        if not keys:
            return None
        key = keys[0]
        credkey = f'{self._prefix}:credentials:{key}'
        data = self._redis.get(credkey)
        if not data:
            return None
        reader = StringIO(data)
        return credentials.Credentials.from_shared_credentials_file(reader,
                                                                  profile_name='credentials')

    def _delete_credentials_by_key(self, access_key: str, purging=False) -> None:
        credkey = f'{self._prefix}:credentials:{access_key}'
        self._redis.delete(credkey)
        cred_id_key = f'{self._prefix}:credentials:{access_key}:identity'
        identity_key = self._redis.get(cred_id_key)

        if identity_key:
            self._redis.delete(cred_id_key)
            if not purging:
                id_creds_key = identity_key.replace('identity', 'idcredentials')
                self._redis.zrem(id_creds_key, access_key)

    def delete_credentials_by_key(self, access_key: str) -> None:
        self._delete_credentials_by_key(access_key)

    def purge_identity_credentials(self, identity: IdentityHandle) -> None:
        cred_id_key = self._get_key_from_handle(identity, namespace='idcredentials')
        keys = self._redis.zrange(cred_id_key, 0, -1)
        for key in keys:
            self._delete_credentials_by_key(key, purging=True)
        self._redis.delete(cred_id_key)

    def get_credentials_by_key(self, access_key: str) -> credentials.Credentials | None:
        credkey = f'{self._prefix}:credentials:{access_key}'
        data = self._redis.get(credkey)
        if not data:
            return None
        reader = StringIO(data)
        return credentials.Credentials.from_shared_credentials_file(reader,
                                                                  profile_name='credentials')
    def get_statistics(self) -> Statistics:
        identity_count = 0
        role_count = 0
        credential_count = 0
        account_count = 0
        max_cred_count = 0
        for key in self._redis.scan_iter(f'{self._prefix}:identity:*'):
            identity_count += 1
            if key.startswith(f'{self._prefix}:identity:role:'):
                role_count += 1
        for key in self._redis.scan_iter(f'{self._prefix}:account:*'):
            account_count += 1
        for key in self._redis.scan_iter(f'{self._prefix}:credentials:*'):
            if not key.endswith(':identity'):
                credential_count += 1
        for key in self._redis.scan_iter(f'{self._prefix}:idcredentials:*'):
            max_cred_count = max(max_cred_count, self._redis.zcard(key))
        return Statistics(identity_count, credential_count, role_count,
                          account_count, max_cred_count)

    def list_identities(self) -> Iterator[IdentityHandle]:
        for key in self._redis.sort(f'{self._prefix}:identities', alpha=True):
            data = self._get_handle_from_key(key)
            if data:
                yield data

    def list_identity_credentials(self, identity: IdentityHandle) -> Iterator[CredentialInfo]:
        id_creds_key = self._get_key_from_handle(identity, namespace='idcredentials')
        keys = self._redis.zrange(id_creds_key, 0, -1, withscores=True, desc=True)
        for key in keys:
            credkey = f'{self._prefix}:credentials:{key[0]}'
            data = self._redis.get(credkey)
            if not data:
                continue
            yield CredentialInfo(key[0], datetime.fromtimestamp(key[1]))
