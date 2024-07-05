from typing import Protocol, runtime_checkable
from enum import Enum

class CredentialType(Enum):
    """Enum to represent the type of AWS credentials."""
    USER = 'user'
    ROLE = 'role'
    ASSUMED_ROLE = 'role'
    UNKNOWN = 'unknown'

@runtime_checkable
class IdentityHandle(Protocol):
    @property
    def account_id(self) -> int:
        ...
    @property
    def arn(self) -> str:
        ...
    @property
    def cred_type(self) -> CredentialType:
        ...
    @property
    def name(self) -> str:
        ...
    def __eq__(self, other: object) -> bool:
        ...
    def __hash__(self) -> int:
        ...
