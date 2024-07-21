from multicred.credentials import Credentials

def test_role_credentials(role_credentials):
    creds = role_credentials.test_object
    assert creds.aws_access_key_id == role_credentials.access_key_id
    assert creds.aws_secret_access_key == role_credentials.secret_access_key
    assert creds.aws_session_token == role_credentials.session_token
    assert creds.is_valid
    assert creds.aws_identity.aws_identity == \
        'arn:aws:sts::123456789012:assumed-role/test_role/test_session'
    # does not work with moto
    #assert creds.aws_identity.aws_userid == role_credentials.userid
    assert creds.aws_identity.aws_role_session_name == 'test_session'
    assert creds.aws_identity.cred_type.value == 'role'
    assert creds.aws_identity.aws_account_id == '123456789012'
    assert creds.aws_identity.aws_role_name == 'test_role'

def test_user_credentials(user_credentials):
    creds = user_credentials.test_object
    assert creds.aws_access_key_id == user_credentials.access_key_id
    assert creds.aws_secret_access_key == user_credentials.secret_access_key
    assert creds.aws_session_token is None
    assert creds.is_valid
    assert creds.aws_identity.aws_identity == 'arn:aws:iam::123456789012:user/test_user'
    assert creds.aws_identity.aws_userid == user_credentials.userid
    assert creds.aws_identity.cred_type.value == 'user'
    assert creds.aws_identity.aws_account_id == '123456789012'
    assert creds.aws_identity.aws_user_name == 'test_user'

def test_credentials_export(role_credentials, user_credentials):
    config = role_credentials.test_object.put()
    assert "credentials" in config
    assert config.get("credentials", "aws_access_key_id") == role_credentials.access_key_id
    assert config.get("credentials", "aws_secret_access_key") == role_credentials.secret_access_key
    assert config.get("credentials", "aws_session_token") == role_credentials.session_token

    config = user_credentials.test_object.put()
    assert "credentials" in config
    assert config.get("credentials", "aws_access_key_id") == user_credentials.access_key_id
    assert config.get("credentials", "aws_secret_access_key") == user_credentials.secret_access_key
    assert not config.has_option("credentials", "aws_session_token")
    
def test_credentials_import(role_credentials, user_credentials):
    data = (
        '[credentials]',
        'aws_access_key_id = ' + role_credentials.access_key_id,
        'aws_secret_access_key = ' + role_credentials.secret_access_key,
        'aws_session_token = ' + role_credentials.session_token
    )
 
    imported_creds = Credentials.from_shared_credentials_file(data, profile_name='credentials')
    assert imported_creds == role_credentials.test_object

    data = (
        '[credentials]',
        'aws_access_key_id = ' + user_credentials.access_key_id,
        'aws_secret_access_key = ' + user_credentials.secret_access_key
    )
    imported_creds = Credentials.from_shared_credentials_file(data, profile_name='credentials')
    assert imported_creds == user_credentials.test_object
