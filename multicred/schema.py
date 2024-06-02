import datetime
from sqlalchemy import String, DateTime, UniqueConstraint, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass
class AwsAccountStorage(Base):
    __tablename__ = 'aws_account'
    id : Mapped[int] = mapped_column(primary_key=True)
    identities = relationship('AwsIdentityStorage', back_populates='aws_account')
    account_id : Mapped[str] = mapped_column(String(20), nullable=False, unique=True)
    created_at : Mapped[datetime.datetime]= mapped_column(default=datetime.datetime.now)
    updated_at : Mapped[datetime.datetime] = mapped_column(default=datetime.datetime.now,
                                                           onupdate=datetime.datetime.now)

class AwsRoleIdentitySourceStorage(Base):
    __tablename__ = 'aws_role_identity_source'
    id : Mapped[int] = mapped_column(primary_key=True)
    target_aws_identity_id : Mapped[int] = mapped_column(ForeignKey('aws_identity.id'),
                                                         unique=True, nullable=False)
    target_aws_identity = relationship('AwsIdentityStorage', back_populates='source_identity',
                                       foreign_keys=[target_aws_identity_id])
    parent_aws_identity_id : Mapped[int] = mapped_column(ForeignKey('aws_identity.id'),
                                                         nullable=False)
    parent_aws_identity = relationship('AwsIdentityStorage', back_populates='derived_identities',
                                       foreign_keys=[parent_aws_identity_id])
    role_arn : Mapped[str] = mapped_column(String(100), nullable=False)
    created_at : Mapped[datetime.datetime] = mapped_column(DateTime, default=datetime.datetime.now)
    updated_at : Mapped[datetime.datetime] = mapped_column(DateTime, default=datetime.datetime.now,
                                                           onupdate=datetime.datetime.now)

class AwsIdentityStorage(Base):
    __tablename__ = 'aws_identity'
    __table_args__ = (UniqueConstraint('aws_account_id', 'cred_type', 'name', name='unique_identity'),)
    id : Mapped[int] = mapped_column(primary_key=True)
    arn : Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    aws_account_id : Mapped[int ]= mapped_column(ForeignKey('aws_account.id'), nullable=False)
    aws_account = relationship('AwsAccountStorage', back_populates='identities')
    userid : Mapped[str] = mapped_column(String(20), nullable=True)
    cred_type : Mapped[str] = mapped_column(String(20), nullable=False)
    name : Mapped[str] = mapped_column(String(100), nullable=False)
    credentials = relationship('AwsCredentialStorage', back_populates='aws_identity')
    source_identity = relationship(
        'AwsRoleIdentitySourceStorage', back_populates='target_aws_identity',
        foreign_keys=[AwsRoleIdentitySourceStorage.target_aws_identity_id])
    derived_identities = relationship(
        'AwsRoleIdentitySourceStorage', back_populates='parent_aws_identity',
        foreign_keys=[AwsRoleIdentitySourceStorage.parent_aws_identity_id])
    created_at :  Mapped[datetime.datetime] = mapped_column(default=datetime.datetime.now)
    updated_at : Mapped[datetime.datetime] = mapped_column(DateTime, default=datetime.datetime.now,
                                                            onupdate=datetime.datetime.now)

class AwsCredentialStorage(Base):
    __tablename__ = 'aws_credential'
    id : Mapped[int] = mapped_column(primary_key=True)
    aws_identity_id : Mapped[str] = mapped_column(ForeignKey('aws_identity.id'))
    aws_identity = relationship('AwsIdentityStorage', back_populates='credentials')
    aws_access_key_id : Mapped[str] = mapped_column(String(20), nullable=False, unique=True)
    aws_secret_access_key : Mapped[str] = mapped_column(String(40), nullable=False)
    aws_session_token : Mapped[str] = mapped_column(String(100), nullable=True)
    created_at : Mapped[datetime.datetime] = mapped_column(DateTime, default=datetime.datetime.now)
    updated_at : Mapped[datetime.datetime] = mapped_column(DateTime, default=datetime.datetime.now,
                                                           onupdate=datetime.datetime.now)
  