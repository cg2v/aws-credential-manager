from .interfaces import Resolver, Storage
from .storage import DBStorage
from .resolver import DBResolver

def get_resolver(db_uri: str) -> Resolver:
    storage = DBStorage(db_uri)
    return DBResolver(storage)

def get_storage(db_uri: str) -> Storage:
    return DBStorage(db_uri)
