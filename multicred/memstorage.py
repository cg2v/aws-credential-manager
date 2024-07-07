from typing import Tuple
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime

from . import credentials
from .interfaces import IdentityHandle, Statistics, CredentialInfo


@dataclass
class MemStorageIdentityData:
    identity: credentials.AwsIdentity
    my_creds: list[credentials.Credentials] = field(default_factory=list, repr=False, compare=False)
    cred_time: dict[str, datetime] = field(default_factory=dict, repr=False, compare=False)
    parent_identity: IdentityHandle | None = field(default=None, repr=False, compare=False)
    role_arn: str | None = field(default=None, repr=False, compare=False)
@dataclass
class MemStorageAccountData:
    account_id: int
    identities: list[MemStorageIdentityData]

class MemStorage:
    accounts: dict[int, MemStorageAccountData]
    identities: dict[str, MemStorageIdentityData]
    id_lookup: dict[Tuple[int, credentials.CredentialType, str], str]
    def __init__(self):
        self.accounts = {}
        self.identities = {}
        self.id_lookup = {}
    def get_identity_by_arn(self, arn: str) -> IdentityHandle | None:
        data = self.identities.get(arn, None)
        if data is None:
            return None
        return data.identity
    def get_identity_by_account_and_role_name(self, account_id: str, role_name: str) \
        -> IdentityHandle | None:
        account = self.accounts.get(int(account_id), None)
        if account is None:
            return None
        for identity in account.identities:
            if isinstance(identity.identity, credentials.AwsRoleIdentity) and \
                identity.identity.aws_role_name == role_name:
                return identity.identity
        return None
    def get_parent_identity(self, identity: IdentityHandle) \
        -> Tuple[IdentityHandle, str] | tuple[None, None]:
        data = self.identities.get(identity.arn, None)
        if data is None:
            return None, None
        if data.parent_identity is None:
            return None, None
        assert data.role_arn is not None
        parent = self.identities[data.parent_identity.arn]
        return parent.identity, data.role_arn
    def construct_identity_relationship(self, creds: credentials.Credentials,
                                  parent_creds: credentials.Credentials,
                                  role_arn: str) \
                                    -> None:
        target = self.identities.get(creds.aws_identity.aws_identity)
        new_parent = self.identities.get(parent_creds.aws_identity.aws_identity)
        if target is None or new_parent is None:
            raise ValueError('Identity not found')
        if target.parent_identity is not None:
            raise ValueError('Identity already has a parent')
        target.parent_identity = new_parent.identity
        target.role_arn = role_arn

    def remove_identity_relationship(self, identity: IdentityHandle) -> None:
        target = self.identities.get(identity.arn)
        assert target is not None
        for search_identity in self.identities.values():
            if search_identity.parent_identity is not None and \
                search_identity.parent_identity.arn == identity.arn:
                raise ValueError('Identity is a parent')
        target.parent_identity = None
        target.role_arn = None

    def import_credentials(self, creds: credentials.Credentials, force: bool = False) -> None:
        identity = creds.aws_identity
        account_id = int(identity.aws_account_id)
        if account_id not in self.accounts:
            self.accounts[account_id] = MemStorageAccountData(
                account_id=account_id,
                identities=[]
            )
        if identity.aws_identity not in self.identities:
            new_identity = MemStorageIdentityData(
                identity=identity
            )
            self.identities[creds.aws_identity.aws_identity] = new_identity
            for search_identity in self.accounts[account_id].identities:
                if search_identity == new_identity:
                    break
            else:
                self.accounts[account_id].identities.append(new_identity)
            id_key = (account_id, identity.cred_type, identity.name)
            self.id_lookup[id_key] = identity.aws_identity
        target_id = self.identities[creds.aws_identity.aws_identity]
        target_id.my_creds.append(creds)
        target_id.cred_time[creds.aws_access_key_id] = datetime.now()
    def get_identity_credentials(self, identity: IdentityHandle) \
        -> credentials.Credentials | None:
        data = self.identities.get(identity.arn)
        if data is None:
            return None
        if not data.my_creds:
            return None
        return data.my_creds[-1]
    def delete_credentials_by_key(self, access_key: str) -> None:
        for identity in self.identities.values():
            identity.my_creds = [c for c in identity.my_creds if c.aws_access_key_id != access_key]
    def purge_identity_credentials(self, identity: IdentityHandle) -> None:
        data = self.identities.get(identity.arn)
        if data is None:
            return
        data.my_creds = []
    def get_credentials_by_key(self, access_key: str) -> credentials.Credentials | None:
        for identity in self.identities.values():
            for creds in identity.my_creds:
                if creds.aws_access_key_id == access_key:
                    return creds
        return None
    def get_statistics(self) -> Statistics:
        total_identities = len(self.identities)
        if total_identities == 0:
            return Statistics(0, 0, 0, 0, 0)
        total_credentials = sum(len(i.my_creds) for i in self.identities.values())
        total_roles = sum(1 for i in self.identities.values() if isinstance(i.identity, credentials.AwsRoleIdentity))
        total_accounts = len(self.accounts)
        max_credentials_per_identity = max(len(i.my_creds) for i in self.identities.values())
        return Statistics(
            total_identities=total_identities,
            total_credentials=total_credentials,
            total_roles=total_roles,
            total_accounts=total_accounts,
            max_credentials_per_identity=max_credentials_per_identity
        )
    def list_identities(self) -> Iterator[IdentityHandle]:
        def get_key(identity: MemStorageIdentityData) -> tuple[str, str]:
            return identity.identity.cred_type.value, identity.identity.name
        for identity in sorted(self.identities.values(), key=get_key):
            yield identity.identity
    def list_identity_credentials(self, identity: IdentityHandle) -> Iterator[CredentialInfo]:
        data = self.identities.get(identity.arn)
        if data is None:
            return
        for creds in data.my_creds:
            yield CredentialInfo(
                access_key=creds.aws_access_key_id,
                created_at=data.cred_time[creds.aws_access_key_id]
            )
