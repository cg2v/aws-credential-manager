from typing import Protocol, Tuple
from . import credentials

class IdentityHandle(Protocol):
    @property
    def account_id(self) -> int:
        ...
    @property
    def arn(self) -> str:
        ...
    @property
    def cred_type(self) -> credentials.CredentialType:
        ...
    @property
    def name(self) -> str:
        ...

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
    def import_credentials(self, creds: credentials.Credentials, *, force: bool = False) -> None:
        ...
    def get_identity_credentials(self, identity: IdentityHandle) \
        -> credentials.Credentials | None:
        ...
    def get_credentials_by_key(self, access_key: str) -> credentials.Credentials | None:
        ...
