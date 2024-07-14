from pytest import raises

from sqlalchemy.exc import NoResultFound
from multicred.dbschema import AwsAccountStorage, AwsIdentityStorage, AwsCredentialStorage

def test_empty_storage(empty_storage):
    with empty_storage.session() as session:
        with raises(NoResultFound):
            session.query(AwsAccountStorage).one()
    assert empty_storage.get_credentials_by_key('UNKNOWN') is None


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

    target_stored_id = derived_creds_storage.test_object.get_identity_by_account_and_role_name(
        target_role_identity.aws_account_id, target_role_identity.name)
    assert target_stored_id is not None
    stored_id, role_arn = derived_creds_storage.test_object.get_parent_identity(
        target_stored_id)
    assert stored_id is not None
    assert stored_id.arn == derived_creds_storage.user_creds.test_object.aws_identity.aws_identity
    assert role_arn.startswith('arn:aws:iam::123456789012:role/test_role')

def test_find_parent_identity_none(role_creds_storage):
    target_role_creds = role_creds_storage.credentials.test_object
    target_role_identity = target_role_creds.aws_identity
    assert target_role_identity.cred_type.value == 'role'

    target_stored_id = role_creds_storage.test_object.get_identity_by_account_and_role_name(
        target_role_identity.aws_account_id, target_role_identity.name)
    assert target_stored_id is not None
    stored_id, role_arn = role_creds_storage.test_object.get_parent_identity(
        target_stored_id)
    assert stored_id is None
    assert role_arn is None

def test_remove_parent_identity(derived_creds_storage):
    target_role_creds = derived_creds_storage.role_creds.test_object
    target_role_identity = target_role_creds.aws_identity
    assert target_role_identity.cred_type.value == 'role'

    target_stored_id = derived_creds_storage.test_object.get_identity_by_account_and_role_name(
        target_role_identity.aws_account_id, target_role_identity.name)
    assert target_stored_id is not None
    stored_id, role_arn = derived_creds_storage.test_object.get_parent_identity(
        target_stored_id)
    assert stored_id.arn == derived_creds_storage.user_creds.test_object.aws_identity.aws_identity
    assert role_arn.startswith('arn:aws:iam::123456789012:role/test_role')

    with raises(ValueError):
        derived_creds_storage.test_object.remove_identity_relationship(stored_id)
    derived_creds_storage.test_object.remove_identity_relationship(target_stored_id)
    stored_id_2, role_arn = derived_creds_storage.test_object.get_parent_identity(
        target_stored_id)
    assert stored_id_2 is None
    assert role_arn is None
    derived_creds_storage.test_object.remove_identity_relationship(stored_id)

def test_delete_credentials(multiple_creds_storage):
    test_creds = multiple_creds_storage.credentials.test_object
    test_identity = multiple_creds_storage.test_object.get_identity_by_arn(
        test_creds.aws_identity.aws_identity)
    assert test_identity is not None
    # before the delete, both access keys should be present, and the identity's creds
    # should be the same
    cred_check = multiple_creds_storage.test_object.get_credentials_by_key(
        test_creds.aws_access_key_id)
    assert cred_check is not None
    cred_check_id = multiple_creds_storage.test_object.get_identity_credentials(test_identity)
    assert cred_check_id is not None
    assert cred_check_id.aws_access_key_id == test_creds.aws_access_key_id
    multiple_creds_storage.test_object.delete_credentials_by_key(test_creds.aws_access_key_id)
    # After the delete, the first access key should be gone, but the identity's creds should
    # still be present with a different access key
    cred_check = multiple_creds_storage.test_object.get_credentials_by_key(
        test_creds.aws_access_key_id)
    assert cred_check is None
    cred_check_id = multiple_creds_storage.test_object.get_identity_credentials(test_identity)
    assert cred_check_id is not None
    assert cred_check_id.aws_access_key_id != test_creds.aws_access_key_id
    # delete of absent key should not raise an error
    multiple_creds_storage.test_object.delete_credentials_by_key(test_creds.aws_access_key_id)


def test_purge_credentials(multiple_creds_storage):
    test_creds = multiple_creds_storage.credentials.test_object
    test_identity = multiple_creds_storage.test_object.get_identity_by_arn(
        test_creds.aws_identity.aws_identity)
    assert test_identity is not None
    # before the delete, both access keys should be present, and the identity's creds
    # should be the same
    cred_check = multiple_creds_storage.test_object.get_credentials_by_key(
        test_creds.aws_access_key_id)
    assert cred_check is not None
    cred_check_id = multiple_creds_storage.test_object.get_identity_credentials(test_identity)
    assert cred_check_id is not None
    assert cred_check_id.aws_access_key_id == test_creds.aws_access_key_id
    multiple_creds_storage.test_object.purge_identity_credentials(test_identity)
    # After the delete, the first access key should be gone, and the identity's creds should
    # be gone as well
    cred_check = multiple_creds_storage.test_object.get_credentials_by_key(
        test_creds.aws_access_key_id)
    assert cred_check is None
    cred_check_id = multiple_creds_storage.test_object.get_identity_credentials(test_identity)
    assert cred_check_id is None
    stats = multiple_creds_storage.test_object.get_statistics()
    assert stats.total_identities == 2
    assert stats.total_credentials == 1
    assert stats.total_roles == 1

def test_statistics_empty(empty_storage):
    stats = empty_storage.get_statistics()
    assert stats.total_identities == 0
    assert stats.total_credentials == 0
    assert stats.total_roles == 0
    assert stats.max_credentials_per_identity == 0

def test_statistics_role(role_creds_storage):
    stats = role_creds_storage.test_object.get_statistics()
    assert stats.total_identities == 1
    assert stats.total_credentials == 1
    assert stats.total_roles == 1
    assert stats.max_credentials_per_identity == 1

def test_statistics_user(user_creds_storage):
    stats = user_creds_storage.test_object.get_statistics()
    assert stats.total_identities == 1
    assert stats.total_credentials == 1
    assert stats.total_roles == 0
    assert stats.max_credentials_per_identity == 1

def test_statistics_multiple(multiple_creds_storage):
    stats = multiple_creds_storage.test_object.get_statistics()
    assert stats.total_identities == 2
    assert stats.total_credentials == 3
    assert stats.total_roles == 1
    assert stats.max_credentials_per_identity == 2

def test_statistics_derived(derived_creds_storage):
    stats = derived_creds_storage.test_object.get_statistics()
    assert stats.total_identities == 2
    assert stats.total_credentials == 2
    assert stats.total_roles == 1
    assert stats.max_credentials_per_identity == 1

def test_list_identities_empty(empty_storage):
    identities = list(empty_storage.list_identities())
    assert isinstance(identities, list)
    assert not identities

def test_list_identities_role(role_creds_storage):
    identities = list(role_creds_storage.test_object.list_identities())
    assert len(identities) == 1
    assert identities[0].arn == 'arn:aws:sts::123456789012:assumed-role/test_role/test_session'
    assert identities[0].account_id == '123456789012'
    assert identities[0].name == 'test_role'

def test_list_identities_user(user_creds_storage):
    identities = list(user_creds_storage.test_object.list_identities())
    assert len(identities) == 1
    assert identities[0].arn == 'arn:aws:iam::123456789012:user/test_user'
    assert identities[0].account_id == '123456789012'
    assert identities[0].name == 'test_user'

def test_list_identities_multiple(multiple_creds_storage):
    identities = list(multiple_creds_storage.test_object.list_identities())
    assert len(identities) == 2
    assert identities[0].arn == 'arn:aws:sts::123456789012:assumed-role/test_role/test_session'
    assert identities[0].account_id == '123456789012'
    assert identities[0].name == 'test_role'
    assert identities[1].arn == 'arn:aws:iam::123456789012:user/test_user'
    assert identities[1].account_id == '123456789012'
    assert identities[1].name == 'test_user'

def test_list_identities_derived(derived_creds_storage):
    identities = list(derived_creds_storage.test_object.list_identities())
    assert len(identities) == 2
    assert identities[0].arn == 'arn:aws:sts::123456789012:assumed-role/test_role/test_session'
    assert identities[0].account_id == '123456789012'
    assert identities[0].name == 'test_role'
    assert identities[1].arn == 'arn:aws:iam::123456789012:user/test_user'
    assert identities[1].account_id == '123456789012'
    assert identities[1].name == 'test_user'

def test_list_identity_credentials_empty(empty_storage):
    identities = list(empty_storage.list_identities())
    assert isinstance(identities, list)
    assert not identities

def test_list_identity_credentials_role(role_creds_storage):
    identities = list(role_creds_storage.test_object.list_identities())
    assert len(identities) == 1
    creds = list(role_creds_storage.test_object.list_identity_credentials(identities[0]))
    assert len(creds) == 1
    assert creds[0].access_key == role_creds_storage.credentials.test_object.aws_access_key_id

def test_list_identity_credentials_user(user_creds_storage):
    identities = list(user_creds_storage.test_object.list_identities())
    assert len(identities) == 1
    creds = list(user_creds_storage.test_object.list_identity_credentials(identities[0]))
    assert len(creds) == 1
    assert creds[0].access_key == user_creds_storage.credentials.test_object.aws_access_key_id

def test_list_identity_credentials_multiple(multiple_creds_storage):
    identities = list(multiple_creds_storage.test_object.list_identities())
    assert len(identities) == 2
    creds = list(multiple_creds_storage.test_object.list_identity_credentials(identities[0]))
    assert len(creds) == 2
    access_keys = {creds[0].access_key, creds[1].access_key}
    assert multiple_creds_storage.credentials.test_object.aws_access_key_id in access_keys
    assert creds[0].access_key != creds[1].access_key
    creds = list(multiple_creds_storage.test_object.list_identity_credentials(identities[1]))
    assert len(creds) == 1
    assert creds[0].access_key not in access_keys
    assert creds[0].access_key != multiple_creds_storage.credentials.test_object.aws_access_key_id
