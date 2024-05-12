from typing import Type
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import NoResultFound, MultipleResultsFound, IntegrityError

from . import schema
from . import credentials


class Storage:
    def __init__(self, db_uri):
        self.engine = create_engine(db_uri)
        schema.Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    # https://stackoverflow.com/a/21146492
    def get_one_or_create(self,
                          session: Session,
                          model: Type[schema.Base],
                          create_method='',
                          create_method_kwargs=None,
                          **kwargs):
        try:
            return session.query(model).filter_by(**kwargs).one(), True
        except NoResultFound:
            kwargs.update(create_method_kwargs or {})
            try:
                with session.begin_nested():
                    created = getattr(model, create_method, model)(**kwargs)
                    session.add(created)
                return created, False
            except IntegrityError:
                return session.query(model).filter_by(**kwargs).one(), True

    def import_credentials(self, creds: credentials.Credentials):
        session = self.Session()
        identity = creds.aws_identity
        account, _ = self.get_one_or_create(session, schema.AwsAccountStorage, account_id=identity.aws_account_id)
        assert isinstance(account, schema.AwsAccountStorage)
        if identity.cred_type == 'role':
            assert isinstance(identity, credentials.AwsRoleIdentity)
            stored_id, _ = self.get_one_or_create(session, schema.AwsIdentityStorage, aws_account=account,
                                                 cred_type=identity.cred_type, name=identity.aws_role_name,
                                                  create_method_kwargs={'arn': identity.aws_identity})
        elif identity.cred_type == 'user':
            assert isinstance(identity, credentials.AwsUserIdentity)
            stored_id, _ = self.get_one_or_create(session, schema.AwsIdentityStorage, aws_account=account,
                                                  cred_type=identity.cred_type, name=identity.aws_user_name,
                                                  create_method_kwargs={'arn': identity.aws_identity})
        else:
            raise ValueError('Unknown cred_type')
        credential = schema.AwsCredentialStorage(aws_identity=stored_id, aws_access_key_id=creds.aws_access_key_id,
                                                 aws_secret_access_key=creds.aws_secret_access_key,
                                                 aws_session_token=creds.aws_session_token)
        session.add(credential)
        session.commit()
        session.close()
    def add_account(self, account_id):
        session = self.Session()
        account = schema.AwsAccountStorage(account_id=account_id)
        session.add(account)
        session.commit()
        session.close()

    def get_account(self, account_id):
        session = self.Session()
        try:
            account = session.query(schema.AwsAccountStorage).filter_by(
                account_id=account_id).one()
        except NoResultFound:
            account = None
        session.close()
        return account

    def add_identity(self, account_id, identity: credentials.AwsIdentity):
        session = self.Session()
        account = session.query(schema.AwsAccountStorage).filter_by(
            account_id=account_id).one()
        if isinstance(identity, credentials.AwsRoleIdentity):
            name = identity.aws_role_name
        elif isinstance(identity, credentials.AwsUserIdentity):
            name = identity.aws_user_name
        else:
            name = 'unknown'
        stored_id = schema.AwsIdentityStorage(aws_identity=identity.aws_identity, aws_account_id=account.id,
                                              cred_type=identity.cred_type, name=name)
        session.add(stored_id)
        session.commit()
        session.close()

    def get_identity(self, account_id, identity):
        session = self.Session()
        try:
            account = session.query(schema.AwsAccountStorage).filter_by(
                account_id=account_id).one()
            identity = session.query(schema.AwsIdentityStorage).filter_by(
                aws_account_id=account.id, aws_identity=identity).one()
        except NoResultFound:
            identity = None
        session.close()
        return identity

    def add_credential(self, identity, credential):
        session = self.Session()
        identity = session.query(schema.AwsIdentityStorage).filter_by(
            aws_identity=identity).one()
        credential = schema.AwsCredentialStorage(aws_identity_id=identity.id, aws_access_key_id=credential.aws_access_key_id,
                                                 aws_secret_access_key=credential.aws_secret_access_key, aws_session_token=credential.aws_session_token)
        session.add(credential)
        session.commit()
        session.close()

    def get_credential(self, identity):
        session = self.Session()
        try:
            identity = session.query(schema.AwsIdentityStorage).filter_by(
                aws_identity=identity).one()
            credential = session.query(schema.AwsCredentialStorage).filter_by(
                aws_identity_id=identity.id).one()
        except NoResultFound:
            credential = None
        session.close()
        return credential
