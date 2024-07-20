from typing import Type
from collections.abc import Iterator
from sqlalchemy import create_engine, Engine, func
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import NoResultFound, IntegrityError, MultipleResultsFound

from . import dbschema
from . import credentials
from .base_objects import MultiCredStorageError, MultiCredLinkError, MultiCredBadRequest
from .interfaces import IdentityHandle, Statistics, CredentialInfo

class DBStorageError(MultiCredStorageError):
    pass

class MissingIdentityError(DBStorageError):
    pass

class DBStorageIdentityHandle:
    data: dbschema.AwsIdentityStorage
    def __init__(self, data: dbschema.AwsIdentityStorage):
        self.data = data
    @property
    def account_id(self) -> str:
        account : dbschema.AwsAccountStorage = self.data.aws_account
        return account.account_id
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
    def _get_one_or_create(self,
                          session: Session,
                          model: Type[dbschema.Base],
                          create_method='',
                          create_method_kwargs=None,
                          **kwargs):
        try:
            return session.query(model).filter_by(**kwargs).with_for_update().one(), True
        except NoResultFound:
            pass
        update_kwargs = kwargs.copy()
        update_kwargs.update(create_method_kwargs or {})
        try:
            with session.begin_nested():
                created: dbschema.Base = getattr(
                    model, create_method, model)(**update_kwargs)
                session.add(created)
            return created, False
        except IntegrityError:
            pass
        try:
            return session.query(model).filter_by(**kwargs).with_for_update().one(), True
        except NoResultFound as e:
            raise DBStorageError('Failed to create or get object') from e


    def _get_db_identity(self, session: Session, identity: IdentityHandle) -> dbschema.AwsIdentityStorage:
        if isinstance(identity, DBStorageIdentityHandle):
            rv = session.get(dbschema.AwsIdentityStorage, identity.data.id)
            if rv is not None:
                return rv
        alt_id = self._get_identity_by_arn(session, identity.arn)
        if alt_id is None:
            raise MissingIdentityError('Identity not found in database.')
        assert isinstance(alt_id, DBStorageIdentityHandle)
        return alt_id.data

    def import_credentials(self, creds: credentials.Credentials):
        if not creds.is_valid:
            raise MultiCredBadRequest('Invalid credentials cannot be imported')
        identity = creds.aws_identity
        with self.session() as session:
            try:
                account, _ = self._get_one_or_create(
                    session, dbschema.AwsAccountStorage, account_id=identity.aws_account_id)
                assert isinstance(account, dbschema.AwsAccountStorage)
                stored_id, _ = self._get_one_or_create(
                    session, dbschema.AwsIdentityStorage, aws_account=account,
                    cred_type=identity.cred_type.value, name=identity.name,
                    create_method_kwargs={'arn': identity.aws_identity, 'userid': identity.aws_userid})
                credential = dbschema.AwsCredentialStorage(
                    aws_identity=stored_id, aws_access_key_id=creds.aws_access_key_id,
                    aws_secret_access_key=creds.aws_secret_access_key,
                    aws_session_token=creds.aws_session_token)
                session.add(credential)
                session.commit()
            except (IntegrityError, NoResultFound, MultipleResultsFound) as e:
                session.rollback()
                raise DBStorageError('Failed to import credentials') from e

    def _get_identity_by_arn(self, session: Session, arn: str) -> IdentityHandle | None:
        try:
            stored_id = session.query(dbschema.AwsIdentityStorage).filter_by(
                arn=arn).one()
        except NoResultFound:
            return None
        return DBStorageIdentityHandle(stored_id)

    def get_identity_by_arn(self, arn: str) -> IdentityHandle | None:
        with self.session() as session:
            return self._get_identity_by_arn(session, arn)

    def get_identity_credentials(self, identity: IdentityHandle) -> credentials.Credentials | None:
        with self.session() as session:
            try:
                db_id = self._get_db_identity(session, identity)
            except MissingIdentityError:
                return None
            if len(db_id.credentials) == 0:
                return None
            credential = db_id.credentials[0]
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

    def _get_identity_by_account_and_role_name(self, session: Session, account_id: str,
                                               role_name: str) -> IdentityHandle | None:
        try:
            account = session.query(dbschema.AwsAccountStorage).filter_by(
                account_id=account_id).one()
            stored_id = session.query(dbschema.AwsIdentityStorage).filter_by(
                aws_account_id=account.id, name=role_name).one()
        except NoResultFound:
            return None
        return DBStorageIdentityHandle(stored_id)

    def get_identity_by_account_and_role_name(self, account_id: str, role_name: str) -> IdentityHandle | None:
        with self.session() as session:
            return self._get_identity_by_account_and_role_name(session, account_id, role_name)

    def get_parent_identity(self, identity: IdentityHandle):
        with self.session() as session:
            try:
                db_id = self._get_db_identity(session, identity)
            except MissingIdentityError:
                return None, None
            if len(db_id.source_identity) == 0:
                return None, None
            parent : dbschema.AwsRoleIdentitySourceStorage = db_id.source_identity[0]
            stored_id : dbschema.AwsIdentityStorage = parent.parent_aws_identity
            return DBStorageIdentityHandle(stored_id), parent.role_arn

    def construct_identity_relationship(self, creds: credentials.Credentials, parent_creds:
                                        credentials.Credentials, role_arn: str):
        with self.session() as session:
            stored_target = self._get_identity_by_arn(session, creds.aws_identity.aws_identity)
            stored_parent = self._get_identity_by_arn(session, parent_creds.aws_identity.aws_identity)
            if stored_target is None or stored_parent is None:
                raise MultiCredLinkError('Identity not found in database. Import credentials before creating links')
            assert isinstance(stored_target, DBStorageIdentityHandle)
            assert isinstance(stored_parent, DBStorageIdentityHandle)
            stored_target_id = stored_target.data
            stored_parent_id = stored_parent.data
            try:
                stored_relationship = dbschema.AwsRoleIdentitySourceStorage(
                    target_aws_identity=stored_target_id, parent_aws_identity=stored_parent_id,
                    role_arn=role_arn)
                session.add(stored_relationship)
                session.commit()
            except IntegrityError as e:
                raise MultiCredLinkError('Failed to create relationship - already exists') from e

    def remove_identity_relationship(self, identity: IdentityHandle):
        with self.session() as session:
            try:
                db_id = self._get_db_identity(session, identity)
            except MissingIdentityError as e:
                raise MultiCredLinkError('Identity not found in database.') from e
            try:
                session.query(dbschema.AwsRoleIdentitySourceStorage).filter_by(
                    parent_aws_identity=db_id).one()
                session.commit()
            except NoResultFound:
                pass
            else:
                raise MultiCredLinkError('This identity is a parent identity and cannot be removed')
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
        with self.session() as session:
            try:
                db_id = self._get_db_identity(session, identity)
            except MissingIdentityError:
                return
            try:
                db_id.credentials.clear()
                session.commit()
            except NoResultFound:
                pass
    def get_statistics(self) -> Statistics:
        with self.session() as session:
            identity_count=session.query(dbschema.AwsIdentityStorage).count()
            credential_count=session.query(dbschema.AwsCredentialStorage).count()
            account_count=session.query(dbschema.AwsAccountStorage).count()
            role_count=session.query(dbschema.AwsIdentityStorage).filter_by(
                cred_type='role').count()
            count=func.count(dbschema.AwsCredentialStorage.aws_identity_id) # pylint: disable=not-callable
            max_credq_query = session.query(count.label('count')).group_by(
                dbschema.AwsCredentialStorage.aws_identity_id).order_by(
                    count.desc()).limit(1)
            try:
                max_credentials_per_identity = max_credq_query.one()[0]
            except NoResultFound:
                max_credentials_per_identity = 0
            return Statistics(
                total_identities=identity_count,
                total_credentials=credential_count,
                total_accounts=account_count,
                total_roles=role_count,
                max_credentials_per_identity=max_credentials_per_identity)
    def list_identities(self) -> Iterator[IdentityHandle]:
        for row in self.session().query(dbschema.AwsIdentityStorage).order_by(
                dbschema.AwsIdentityStorage.cred_type.asc(),
                dbschema.AwsIdentityStorage.name.asc()
            ).all():
            yield DBStorageIdentityHandle(row)
    def list_identity_credentials(self, identity: IdentityHandle) -> Iterator[CredentialInfo]:
        with self.session() as session:
            try:
                db_id = self._get_db_identity(session, identity)
            except MissingIdentityError:
                return
            for row in db_id.credentials:
                yield CredentialInfo(
                    access_key=row.aws_access_key_id,
                    created_at=row.created_at)
