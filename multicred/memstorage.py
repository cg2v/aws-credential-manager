from typing import Tuple
from dataclasses import dataclass, field
import warnings

from . import credentials
from .base_objects import IdentityKey, IdentityHandle, MultiCredLinkError, MultiCredBadRequest
from .utils import parse_principal


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
    accounts: set[str]
    identities: dict[IdentityKey, MemStorageIdentityData]
    def __init__(self):
        self.accounts = set()
        self.identities = {}
    def _get_identity(self, handle: IdentityHandle) -> MemStorageIdentityData | None:
        key = IdentityKey(handle.cred_type, handle.aws_account_id, handle.name)
        return self.identities.get(key, None)
    def get_identity_by_arn(self, arn: str) -> IdentityHandle | None:
        try:
            key = parse_principal(arn)
        except ValueError:
            return None
        data = self.identities.get(key, None)
        if data is None:
            return None
        return data.identity
    def get_identity_by_account_and_role_name(self, account_id: str, role_name: str) \
        -> IdentityHandle | None:
        key = IdentityKey(credentials.CredentialType.ROLE, account_id, role_name)
        identity = self.identities.get(key, None)
        if identity is None:
            return None
        return identity.identity
    def get_parent_identity(self, identity: IdentityHandle) \
        -> Tuple[IdentityHandle, str] | tuple[None, None]:
        data = self._get_identity(identity)
        if data is None:
            return None, None
        if data.parent_identity is None:
            return None, None
        assert data.role_arn is not None
        parent = self._get_identity(data.parent_identity)
        if parent is None:
            warnings.warn('Linked parent identity was not found')
            return None, None
        return parent.identity, data.role_arn
    def construct_identity_relationship(self, creds: credentials.Credentials,
                                  parent_creds: credentials.Credentials,
                                  role_arn: str) \
                                    -> None:
        target = self._get_identity(creds.aws_identity)
        new_parent = self._get_identity(parent_creds.aws_identity)
        if target is None or new_parent is None:
            raise MultiCredLinkError('Identity not found')
        if target.parent_identity is not None:
            raise MultiCredLinkError('Identity already has a parent')
        target.parent_identity = new_parent.identity
        target.role_arn = role_arn

    def remove_identity_relationship(self, identity: IdentityHandle) -> None:
        target = self._get_identity(identity)
        assert target is not None
        for search_identity in self.identities.values():
            if search_identity.parent_identity is not None and \
                search_identity.parent_identity == identity:
                raise MultiCredLinkError('Identity is a parent')
        target.parent_identity = None
        target.role_arn = None

    def import_credentials(self, creds: credentials.Credentials) -> None:
        if not creds.is_valid:
            raise MultiCredBadRequest('Invalid credentials cannot be imported')
        identity = creds.aws_identity
        self.accounts.add(identity.aws_account_id)
        key = IdentityKey(identity.cred_type, identity.aws_account_id, identity.name)
        if key not in self.identities:
            new_identity = MemStorageIdentityData(
                identity=identity
            )
            self.identities[key] = new_identity
        target_id = self.identities[key]
        target_id.my_creds.append(creds)
    def get_identity_credentials(self, identity: IdentityHandle) \
        -> credentials.Credentials | None:
        data = self._get_identity(identity)
        if data is None:
            return None
        if not data.my_creds:
            return None
        return data.my_creds[-1]
    def delete_credentials_by_key(self, access_key: str) -> None:
        for identity in self.identities.values():
            identity.my_creds = [c for c in identity.my_creds if c.aws_access_key_id != access_key]
    def purge_identity_credentials(self, identity: IdentityHandle) -> None:
        data = self._get_identity(identity)
        if data is None:
            return
        data.my_creds = []
    def get_credentials_by_key(self, access_key: str) -> credentials.Credentials | None:
        for identity in self.identities.values():
            for creds in identity.my_creds:
                if creds.aws_access_key_id == access_key:
                    return creds
        return None
