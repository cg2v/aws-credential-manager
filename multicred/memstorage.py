from typing import Tuple
from dataclasses import dataclass, field

from . import credentials
from .base_objects import IdentityHandle, MultiCredLinkError, MultiCredBadRequest


@dataclass
class MemStorageIdentityData:
    identity: credentials.AwsIdentity
    my_creds: list[credentials.Credentials] = field(default_factory=list, repr=False, compare=False)
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
            raise MultiCredLinkError('Identity not found')
        if target.parent_identity is not None:
            raise MultiCredLinkError('Identity already has a parent')
        target.parent_identity = new_parent.identity
        target.role_arn = role_arn

    def remove_identity_relationship(self, identity: IdentityHandle) -> None:
        target = self.identities.get(identity.arn)
        assert target is not None
        for search_identity in self.identities.values():
            if search_identity.parent_identity is not None and \
                search_identity.parent_identity.arn == identity.arn:
                raise MultiCredLinkError('Identity is a parent')
        target.parent_identity = None
        target.role_arn = None

    def import_credentials(self, creds: credentials.Credentials) -> None:
        if not creds.is_valid:
            raise MultiCredBadRequest('Invalid credentials cannot be imported')
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
        self.identities[creds.aws_identity.aws_identity].my_creds.append(creds)
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
