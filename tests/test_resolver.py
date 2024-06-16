def test_empty_resolver(empty_resolver):
    assert empty_resolver.get_credentials_by_arn(
        'arn:aws:sts::123456789012:assumed-role/test_role/test_session') is None
    assert empty_resolver.get_credentials_by_account_and_role_name(
        '123456789012', 'test_role') is None
    

def test_role_resolver_get_arn(role_creds_resolver):
    test_creds = role_creds_resolver.credentials.test_object
    creds = role_creds_resolver.test_object.get_credentials_by_arn(
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

def test_role_resolver_get_id(role_creds_resolver):
    test_creds = role_creds_resolver.credentials.test_object
    creds = role_creds_resolver.test_object.get_credentials_by_account_and_role_name(
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

def test_multiple_creds_for_role(multiple_creds_resolver):
    test_creds = multiple_creds_resolver.credentials.test_object
    creds = multiple_creds_resolver.test_object.get_credentials_by_account_and_role_name(
        test_creds.aws_identity.aws_account_id, test_creds.aws_identity.aws_role_name)
    assert creds.aws_access_key_id == test_creds.aws_access_key_id
    assert creds.aws_secret_access_key == test_creds.aws_secret_access_key

def test_role_resolver_get_derived(derived_creds_resolver):
    test_creds = derived_creds_resolver.role_creds.test_object
    storage = derived_creds_resolver.storage.test_object
    creds = derived_creds_resolver.test_object.get_credentials_by_arn(
        test_creds.aws_identity.aws_identity)
    assert creds.aws_access_key_id == test_creds.aws_access_key_id
    assert creds.aws_secret_access_key == test_creds.aws_secret_access_key
    test_identity = derived_creds_resolver.storage.test_object.get_identity_by_arn(
        test_creds.aws_identity.aws_identity)
    assert test_identity is not None
    storage.delete_credentials_by_key(test_creds.aws_access_key_id)
    creds = derived_creds_resolver.test_object.get_credentials_by_arn(
        test_creds.aws_identity.aws_identity)
    assert creds is not None
    assert creds.aws_access_key_id != test_creds.aws_access_key_id
