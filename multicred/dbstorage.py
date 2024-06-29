from typing import Type
from collections.abc import Iterator
from sqlalchemy import create_engine, Engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import NoResultFound, IntegrityError

from . import dbschema
from . import credentials
from .interfaces import IdentityHandle, Statistics, CredentialInfo

class DBStorageIdentityHandle:
    data: dbschema.AwsIdentityStorage
    def __init__(self, data: dbschema.AwsIdentityStorage):
        self.data = data
    @property
    def account_id(self) -> int:
        return self.data.aws_account_id
    @property
    def arn(self) -> str:
        return self.data.arn
    @property
    def cred_type(self) -> credentials.CredentialType:
        return credentials.CredentialType(self.data.cred_type)
    @property
    def name(self) -> str:
        return self.data.name
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IdentityHandle):
            return False
        return self.arn == other.arn
    def __hash__(self) -> int:
        return hash(self.arn)

class DBStorage:
    engine: Engine
    # https://github.com/sqlalchemy/sqlalchemy/issues/7656
    # not sure why this had to be a string
    session: 'sessionmaker[Session]'

    def __init__(self, db_uri):
        self.engine = create_engine(db_uri)
        dbschema.Base.metadata.create_all(self.engine)
        self.session = sessionmaker(bind=self.engine)

    # https://stackoverflow.com/a/21146492
    def get_one_or_create(self,
                          session: Session,
                          model: Type[dbschema.Base],
                          create_method='',
                          create_method_kwargs=None,
                          **kwargs):
        try:
            return session.query(model).filter_by(**kwargs).with_for_update().one(), True
        except NoResultFound:
            kwargs.update(create_method_kwargs or {})
            try:
                with session.begin_nested():
                    created: dbschema.Base = getattr(
                        model, create_method, model)(**kwargs)
                    session.add(created)
                return created, False
            except IntegrityError:
                return session.query(model).filter_by(**kwargs).one(), True

    def import_credentials(self, creds: credentials.Credentials, force=False):
        session = self.session()
        identity = creds.aws_identity
        account, _ = self.get_one_or_create(
            session, dbschema.AwsAccountStorage, account_id=identity.aws_account_id)
        assert isinstance(account, dbschema.AwsAccountStorage)
        stored_id, _ = self.get_one_or_create(
            session, dbschema.AwsIdentityStorage, aws_account=account,
            cred_type=identity.cred_type.value, name=identity.name,
            create_method_kwargs={'arn': identity.aws_identity, 'userid': identity.aws_userid})
        credential = dbschema.AwsCredentialStorage(
            aws_identity=stored_id, aws_access_key_id=creds.aws_access_key_id,
            aws_secret_access_key=creds.aws_secret_access_key,
            aws_session_token=creds.aws_session_token)
        session.add(credential)
        session.commit()
        session.close()

    def get_identity_by_arn(self, arn: str) -> IdentityHandle | None:
        with self.session() as session:
            try:
                stored_id = session.query(dbschema.AwsIdentityStorage).filter_by(
                    arn=arn).one()
            except NoResultFound:
                return None
        return DBStorageIdentityHandle(stored_id)

    def get_identity_credentials(self, identity: IdentityHandle) -> credentials.Credentials | None:
        if not isinstance(identity, DBStorageIdentityHandle):
            raise ValueError('Identity is not from this storage')
        db_id = identity.data
        with self.session() as session:
            credential = session.query(dbschema.AwsCredentialStorage).filter_by(
                aws_identity=db_id).order_by(
                    dbschema.AwsCredentialStorage.created_at.desc()).first()

        if credential is None:
            return None
        rv = credentials.Credentials(
            aws_access_key_id=credential.aws_access_key_id,
            aws_secret_access_key=credential.aws_secret_access_key,
            aws_session_token=credential.aws_session_token)
        if not rv.is_valid:
            rv.aws_identity = credentials.AwsIdentity(
                aws_identity=identity.arn, aws_userid=db_id.userid)
        return rv


    def get_credentials_by_key(self, access_key: str):
        with self.session() as session:
            try:
                credential = session.query(dbschema.AwsCredentialStorage).filter_by(
                    aws_access_key_id=access_key).one()
                stored_id = session.query(dbschema.AwsIdentityStorage).filter_by(
                    id=credential.aws_identity_id).one()
            except NoResultFound:
                return None
        rv = credentials.Credentials(
            aws_access_key_id=credential.aws_access_key_id,
            aws_secret_access_key=credential.aws_secret_access_key,
            aws_session_token=credential.aws_session_token)
        if not rv.is_valid:
            rv.aws_identity = credentials.AwsIdentity(
                aws_identity=stored_id.arn, aws_userid=stored_id.userid)
        return rv

    def get_identity_by_account_and_role_name(self, account_id: str, role_name: str) -> IdentityHandle | None:
        with self.session() as session:
            try:
                account = session.query(dbschema.AwsAccountStorage).filter_by(
                    account_id=account_id).one()
                stored_id = session.query(dbschema.AwsIdentityStorage).filter_by(
                    aws_account_id=account.id, name=role_name).one()
            except NoResultFound:
                return None
        return DBStorageIdentityHandle(stored_id)

    def get_parent_identity(self, identity: IdentityHandle):
        if not isinstance(identity, DBStorageIdentityHandle):
            raise ValueError('Identity is not from this storage')
        db_id = identity.data
        with self.session() as session:
            try:
                parent = session.query(dbschema.AwsRoleIdentitySourceStorage).filter_by(
                    target_aws_identity_id=db_id.id).one()
                stored_id = session.query(dbschema.AwsIdentityStorage).filter_by(
                    id=parent.parent_aws_identity_id).one()
            except NoResultFound:
                return None, None
        return DBStorageIdentityHandle(stored_id), parent.role_arn

    def construct_identity_relationship(self, creds: credentials.Credentials, parent_creds:
                                        credentials.Credentials, role_arn: str):
        stored_target = self.get_identity_by_arn(creds.aws_identity.aws_identity)
        stored_parent = self.get_identity_by_arn(parent_creds.aws_identity.aws_identity)
        if stored_target is None or stored_parent is None:
            raise ValueError('Identity not found')
        assert isinstance(stored_target, DBStorageIdentityHandle)
        assert isinstance(stored_parent, DBStorageIdentityHandle)
        stored_target_id = stored_target.data
        stored_parent_id = stored_parent.data
        with self.session() as session:
            stored_relationship = dbschema.AwsRoleIdentitySourceStorage(
                target_aws_identity=stored_target_id, parent_aws_identity=stored_parent_id,
                role_arn=role_arn)
            session.add(stored_relationship)
            session.commit()

    def remove_identity_relationship(self, identity: IdentityHandle):
        if not isinstance(identity, DBStorageIdentityHandle):
            raise ValueError('Identity is not from this storage')
        db_id = identity.data
        with self.session() as session:
            try:
                session.query(dbschema.AwsRoleIdentitySourceStorage).filter_by(
                    parent_aws_identity=db_id).one()
                session.commit()
            except NoResultFound:
                pass
            else:
                raise ValueError('This identity is a parent identity and cannot be removed')
            try:
                stored_id = session.query(dbschema.AwsRoleIdentitySourceStorage).filter_by(
                    target_aws_identity=db_id).one()
                session.delete(stored_id)
                session.commit()
            except NoResultFound:
                pass

    def delete_credentials_by_key(self, access_key: str):
        with self.session() as session:
            try:
                credential = session.query(dbschema.AwsCredentialStorage).filter_by(
                    aws_access_key_id=access_key).one()
                session.delete(credential)
                session.commit()
            except NoResultFound:
                pass

    def purge_identity_credentials(self, identity: IdentityHandle):
        if not isinstance(identity, DBStorageIdentityHandle):
            raise ValueError('Identity is not from this storage')
        db_id = identity.data
        with self.session() as session:
            try:
                session.query(dbschema.AwsCredentialStorage).filter_by(
                    aws_identity=db_id).delete()
                session.commit()
            except NoResultFound:
                pass
    def get_statistics(self) -> Statistics:
        ...
    def list_identities(self) -> Iterator[IdentityHandle]:
        ...
    def list_identity_credentials(self, identity: IdentityHandle) -> Iterator[CredentialInfo]:
        ...
