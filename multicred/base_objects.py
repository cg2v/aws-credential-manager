from typing import Protocol, runtime_checkable
from enum import Enum
from dataclasses import dataclass

class CredentialType(Enum):
    """Enum to represent the type of AWS credentials."""
    USER = 'user'
    ROLE = 'role'
    ASSUMED_ROLE = 'role'
    UNKNOWN = 'unknown'

@runtime_checkable
class IdentityHandle(Protocol):
    @property
    def aws_account_id(self) -> str:
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

@dataclass(frozen=True)
class IdentityKey:
    cred_type: CredentialType
    aws_account_id: str
    name: str

class MultiCredError(Exception):
    """Base class for all exceptions in multicred"""

class MultiCredStorageError(MultiCredError):
    """Base class for storage related exceptions"""

class MultiCredResolverError(MultiCredError):
    """Base class for resolver related exceptions"""

class MultiCredBadRequest(MultiCredError, ValueError):
    """Exception raised for bad requests"""

class MultiCredLinkError(MultiCredBadRequest):
    """Exception raised for bad link/unlink requests"""
