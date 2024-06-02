from pytest import raises

from sqlalchemy.exc import NoResultFound
from multicred.schema import AwsAccountStorage, AwsIdentityStorage, AwsCredentialStorage
from multicred.credentials import AwsRoleIdentity

def test_empty_storage(empty_storage):
    with empty_storage.session() as session:
        with raises(NoResultFound):
            session.query(AwsAccountStorage).one()
    assert empty_storage.get_credentials_by_key('UNKNOWN') is None
    assert empty_storage.get_credentials_by_arn(
        'arn:aws:sts::123456789012:assumed-role/test_role/test_session') is None
    assert empty_storage.get_credentials_by_account_and_role_name(
        '123456789012', 'test_role') is None

def test_role_storage_find_key(role_creds_storage):
    with role_creds_storage.test_object.session() as session:
        stored_id = session.query(AwsIdentityStorage).filter_by(
            arn='arn:aws:sts::123456789012:assumed-role/test_role/test_session').one()
        credential = session.query(AwsCredentialStorage).filter_by(
            aws_identity=stored_id).order_by(
                AwsCredentialStorage.created_at.desc()).first()
        assert credential.aws_access_key_id == \
            role_creds_storage.credentials.test_object.aws_access_key_id

def test_role_storage_get_key(role_creds_storage):
    test_creds = role_creds_storage.credentials.test_object
    creds = role_creds_storage.test_object.get_credentials_by_key(test_creds.aws_access_key_id)
    assert creds.aws_access_key_id == test_creds.aws_access_key_id
    assert creds.aws_secret_access_key == test_creds.aws_secret_access_key
    assert creds.aws_session_token == test_creds.aws_session_token
    assert creds.is_valid


def test_role_storage_get_arn(role_creds_storage):
    test_creds = role_creds_storage.credentials.test_object
    creds = role_creds_storage.test_object.get_credentials_by_arn(
        test_creds.aws_identity.aws_identity)
    assert creds.aws_access_key_id == test_creds.aws_access_key_id
    assert creds.aws_secret_access_key == test_creds.aws_secret_access_key
    assert creds.aws_session_token == test_creds.aws_session_token
    assert creds.is_valid
    assert creds.aws_identity.aws_identity == \
        'arn:aws:sts::123456789012:assumed-role/test_role/test_session'
    assert creds.aws_identity.aws_role_session_name == 'test_session'
    assert creds.aws_identity.cred_type.value == 'role'
    assert creds.aws_identity.aws_account_id == '123456789012'
    assert creds.aws_identity.aws_role_name == 'test_role'

def test_role_storage_get_id(role_creds_storage):
    test_creds = role_creds_storage.credentials.test_object
    creds = role_creds_storage.test_object.get_credentials_by_account_and_role_name(
        test_creds.aws_identity.aws_account_id, test_creds.aws_identity.aws_role_name)
    assert creds.aws_access_key_id == test_creds.aws_access_key_id
    assert creds.aws_secret_access_key == test_creds.aws_secret_access_key
    assert creds.aws_session_token == test_creds.aws_session_token
    assert creds.is_valid
    assert creds.aws_identity.aws_identity == \
        'arn:aws:sts::123456789012:assumed-role/test_role/test_session'
    assert creds.aws_identity.aws_role_session_name == 'test_session'
    assert creds.aws_identity.cred_type.value == 'role'
    assert creds.aws_identity.aws_account_id == '123456789012'
    assert creds.aws_identity.aws_role_name == 'test_role'

def test_multiple_creds_for_role(multiple_creds_storage):
    test_creds = multiple_creds_storage.credentials.test_object
    creds = multiple_creds_storage.test_object.get_credentials_by_account_and_role_name(
        test_creds.aws_identity.aws_account_id, test_creds.aws_identity.aws_role_name)
    assert creds.aws_access_key_id == test_creds.aws_access_key_id
    assert creds.aws_secret_access_key == test_creds.aws_secret_access_key

def test_find_identity_by_arn(role_creds_storage):
    stored_id = role_creds_storage.test_object.get_identity_by_arn(
        'arn:aws:sts::123456789012:assumed-role/test_role/test_session')
    assert stored_id.arn == 'arn:aws:sts::123456789012:assumed-role/test_role/test_session'

def test_find_identity_by_account_and_role_name(role_creds_storage):
    stored_id = role_creds_storage.test_object.get_identity_by_account_and_role_name(
        '123456789012', 'test_role')
    assert stored_id.arn == 'arn:aws:sts::123456789012:assumed-role/test_role/test_session'

def test_find_parent_identity(derived_creds_storage):
    target_role_creds = derived_creds_storage.role_creds.test_object
    target_role_identity = target_role_creds.aws_identity
    assert target_role_identity.cred_type.value == 'role'
    assert isinstance(target_role_identity, AwsRoleIdentity)

    target_stored_id = derived_creds_storage.test_object.get_identity_by_account_and_role_name(
        target_role_identity.aws_account_id, target_role_identity.aws_role_name)
    stored_id, role_arn = derived_creds_storage.test_object.get_parent_identity(
        target_stored_id)
    assert stored_id.arn == derived_creds_storage.user_creds.test_object.aws_identity.aws_identity
    assert role_arn.startswith('arn:aws:iam::123456789012:role/test_role')
