from typing import Protocol, Tuple
from dataclasses import dataclass
from collections.abc import Iterator
from datetime import datetime
from .base_objects import IdentityHandle
from . import credentials

@dataclass
class Statistics:
    total_identities: int
    total_credentials: int
    total_roles: int
    total_accounts: int
    max_credentials_per_identity: int

@dataclass
class CredentialInfo:
    access_key: str
    created_at: datetime

class Resolver(Protocol):
    def get_credentials_by_arn(self, arn: str) -> credentials.Credentials | None:
        ...
    def get_credentials_by_key(self, access_key: str) -> credentials.Credentials | None:
        ...
    def get_credentials_by_account_and_role_name(self, account_id: str, role_name: str) \
        -> credentials.Credentials | None:
        ...

class Storage(Protocol):
    def get_identity_by_arn(self, arn: str) -> IdentityHandle | None:
        ...
    def get_identity_by_account_and_role_name(self, account_id: str, role_name: str) \
        -> IdentityHandle | None:
        ...
    def get_parent_identity(self, identity: IdentityHandle) \
        -> Tuple[IdentityHandle, str] | tuple[None, None]:
        ...
    def construct_identity_relationship(self, creds: credentials.Credentials,
                                  parent_creds: credentials.Credentials,
                                  role_arn: str) \
                                    -> None:
        ...
    def remove_identity_relationship(self, identity: IdentityHandle) -> None:
        ...
    def import_credentials(self, creds: credentials.Credentials, *, force: bool = False) -> None:
        ...
    def get_identity_credentials(self, identity: IdentityHandle) \
        -> credentials.Credentials | None:
        ...
    def delete_credentials_by_key(self, access_key: str) -> None:
        ...
    def purge_identity_credentials(self, identity: IdentityHandle) -> None:
        ...
    def get_credentials_by_key(self, access_key: str) -> credentials.Credentials | None:
        ...
    def get_statistics(self) -> Statistics:
        ...
    def list_identities(self) -> Iterator[IdentityHandle]:
        ...
    def list_identity_credentials(self, identity: IdentityHandle) -> Iterator[CredentialInfo]:
        ...
