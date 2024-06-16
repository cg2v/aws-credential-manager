from typing import Type
from sqlalchemy import create_engine, Engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import NoResultFound, IntegrityError

from . import schema
from . import credentials
from .interfaces import IdentityHandle

class DBStorageIdentityHandle:
    data: schema.AwsIdentityStorage
    def __init__(self, data: schema.AwsIdentityStorage):
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

class DBStorage:
    engine: Engine
    # https://github.com/sqlalchemy/sqlalchemy/issues/7656
    # not sure why this had to be a string
    session: 'sessionmaker[Session]'

    def __init__(self, db_uri):
        self.engine = create_engine(db_uri)
        schema.Base.metadata.create_all(self.engine)
        self.session = sessionmaker(bind=self.engine)

    # https://stackoverflow.com/a/21146492
    def get_one_or_create(self,
                          session: Session,
                          model: Type[schema.Base],
                          create_method='',
                          create_method_kwargs=None,
                          **kwargs):
        try:
            return session.query(model).filter_by(**kwargs).with_for_update().one(), True
        except NoResultFound:
            kwargs.update(create_method_kwargs or {})
            try:
                with session.begin_nested():
                    created: schema.Base = getattr(
                        model, create_method, model)(**kwargs)
                    session.add(created)
                return created, False
            except IntegrityError:
                return session.query(model).filter_by(**kwargs).one(), True

    def import_credentials(self, creds: credentials.Credentials, force=False):
        session = self.session()
        identity = creds.aws_identity
        account, _ = self.get_one_or_create(
            session, schema.AwsAccountStorage, account_id=identity.aws_account_id)
        assert isinstance(account, schema.AwsAccountStorage)
        if identity.cred_type == credentials.CredentialType.ROLE:
            assert isinstance(identity, credentials.AwsRoleIdentity)
            stored_id, _ = self.get_one_or_create(
                session, schema.AwsIdentityStorage, aws_account=account,
                cred_type=str(identity.cred_type), name=identity.aws_role_name,
                create_method_kwargs={'arn': identity.aws_identity, 'userid': identity.aws_userid})
        elif identity.cred_type == credentials.CredentialType.USER:
            assert isinstance(identity, credentials.AwsUserIdentity)
            stored_id, _ = self.get_one_or_create(
                session, schema.AwsIdentityStorage, aws_account=account,
                cred_type=str(identity.cred_type), name=identity.aws_user_name,
                create_method_kwargs={'arn': identity.aws_identity, 'userid': identity.aws_userid})
        elif identity.cred_type == credentials.CredentialType.UNKNOWN:
            if not force:
                raise ValueError('Credential is invalid and not indexable')
            stored_id, _ = self.get_one_or_create(
                session, schema.AwsIdentityStorage, aws_account=account,
                cred_type=str(identity.cred_type), name=identity.aws_account_id,
                create_method_kwargs={'arn': identity.aws_identity, 'userid': identity.aws_userid})
        else:
            raise ValueError('Unknown cred_type')
        credential = schema.AwsCredentialStorage(
            aws_identity=stored_id, aws_access_key_id=creds.aws_access_key_id,
            aws_secret_access_key=creds.aws_secret_access_key,
            aws_session_token=creds.aws_session_token)
        session.add(credential)
        session.commit()
        session.close()

    def get_identity_by_arn(self, arn: str) -> IdentityHandle | None:
        with self.session() as session:
            try:
                stored_id = session.query(schema.AwsIdentityStorage).filter_by(
                    arn=arn).one()
            except NoResultFound:
                return None
        return DBStorageIdentityHandle(stored_id)

    def get_identity_credentials(self, identity: IdentityHandle) -> credentials.Credentials | None:
        if not isinstance(identity, DBStorageIdentityHandle):
            raise ValueError('Identity is not from this storage')
        db_id = identity.data
        with self.session() as session:
            credential = session.query(schema.AwsCredentialStorage).filter_by(
                aws_identity=db_id).order_by(
                    schema.AwsCredentialStorage.created_at.desc()).first()

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
                credential = session.query(schema.AwsCredentialStorage).filter_by(
                    aws_access_key_id=access_key).one()
                stored_id = session.query(schema.AwsIdentityStorage).filter_by(
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
                account = session.query(schema.AwsAccountStorage).filter_by(
                    account_id=account_id).one()
                stored_id = session.query(schema.AwsIdentityStorage).filter_by(
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
                parent = session.query(schema.AwsRoleIdentitySourceStorage).filter_by(
                    target_aws_identity_id=db_id.id).one()
                stored_id = session.query(schema.AwsIdentityStorage).filter_by(
                    id=parent.parent_aws_identity_id).one()
            except NoResultFound:
                return None, None
        return DBStorageIdentityHandle(stored_id), parent.role_arn

    def construct_identity_relationship(self, creds: credentials.Credentials, parent_creds:
                                        credentials.Credentials, role_arn: str):
        stored_target_id = self.get_identity_by_arn(creds.aws_identity.aws_identity)
        stored_parent_id = self.get_identity_by_arn(parent_creds.aws_identity.aws_identity)
        if stored_target_id is None or stored_parent_id is None:
            raise ValueError('Identity not found')
        with self.session() as session:
            stored_relationship = schema.AwsRoleIdentitySourceStorage(
                target_aws_identity=stored_target_id, parent_aws_identity=stored_parent_id,
                role_arn=role_arn)
            session.add(stored_relationship)
            session.commit()
