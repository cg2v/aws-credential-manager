from .interfaces import Resolver, Storage
from .dbstorage import DBStorage
from .resolver import StorageBasedResolver
from ._version import __version__

def get_resolver(db_uri: str) -> Resolver:
    storage = DBStorage(db_uri)
    return StorageBasedResolver(storage)

def get_storage(db_uri: str) -> Storage:
    return DBStorage(db_uri)

__all__ = ['Resolver', 'Storage', 'get_resolver', 'get_storage', '__version__']
