import datetime
from sqlalchemy import String, DateTime, UniqueConstraint, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass
class AwsAccountStorage(Base):
    __tablename__ = 'aws_account'
    id : Mapped[int] = mapped_column(primary_key=True)
    account_id : Mapped[str] = mapped_column(String(20), nullable=False, unique=True)
    created_at : Mapped[datetime.datetime]= mapped_column(default=datetime.datetime.now)
    updated_at : Mapped[datetime.datetime] = mapped_column(default=datetime.datetime.now,
                                                           onupdate=datetime.datetime.now)

class AwsIdentityStorage(Base):
    __tablename__ = 'aws_identity'
    __table_args__ = (UniqueConstraint('aws_account_id', 'cred_type', 'name', name='unique_identity'),)
    id : Mapped[int] = mapped_column(primary_key=True)
    arn : Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    aws_account_id : Mapped[int ]= mapped_column(ForeignKey('aws_account.id'), nullable=False)
    aws_account = relationship('AwsAccountStorage', backref='identities')
    cred_type : Mapped[str] = mapped_column(String(20), nullable=False)
    name : Mapped[str] = mapped_column(String(100), nullable=False)
    created_at :  Mapped[datetime.datetime] = mapped_column(default=datetime.datetime.now)
    updated_at : Mapped[datetime.datetime] = mapped_column(DateTime, default=datetime.datetime.now,
                                                            onupdate=datetime.datetime.now)

class AwsCredentialStorage(Base):
    __tablename__ = 'aws_credential'
    id : Mapped[int] = mapped_column(primary_key=True)
    aws_identity_id : Mapped[str] = mapped_column(ForeignKey('aws_identity.id'))
    aws_identity = relationship('AwsIdentityStorage', backref='credentials')
    aws_access_key_id : Mapped[str] = mapped_column(String(20), nullable=False, unique=True)
    aws_secret_access_key : Mapped[str] = mapped_column(String(40), nullable=False)
    aws_session_token : Mapped[str] = mapped_column(String(100), nullable=True)
    created_at : Mapped[datetime.datetime] = mapped_column(DateTime, default=datetime.datetime.now)
    updated_at : Mapped[datetime.datetime] = mapped_column(DateTime, default=datetime.datetime.now,
                                                           onupdate=datetime.datetime.now)
