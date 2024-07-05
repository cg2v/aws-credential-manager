from multicred.base_objects import IdentityHandle, CredentialType

def test_aws_role_identity(role_identity):
    assert role_identity.aws_identity == 'arn:aws:sts::123456789012:assumed-role/test_role/test_session'
    assert role_identity.aws_userid == 'AROAEXAMPLE'
    assert role_identity.aws_role_session_name == 'test_session'
    assert role_identity.cred_type.value == 'role'
    assert role_identity.aws_account_id == '123456789012'
    assert role_identity.aws_role_name == 'test_role'


def testaws_identity_protocol(role_identity, test_identity_handle):
    assert isinstance(role_identity, IdentityHandle)
    assert role_identity.account_id == 123456789012
    assert role_identity.arn == 'arn:aws:sts::123456789012:assumed-role/test_role/test_session'
    assert role_identity.cred_type == CredentialType.ROLE
    assert role_identity.name == 'test_role'
    assert role_identity == 'arn:aws:sts::123456789012:assumed-role/test_role/test_session'
    assert hash(role_identity) == hash('arn:aws:sts::123456789012:assumed-role/test_role/test_session')
    assert role_identity == test_identity_handle

def test_aws_role_identity_repr(role_identity):
    assert repr(role_identity) == "AwsRoleIdentity(aws_userid='AROAEXAMPLE', " \
            "aws_account_id='123456789012', cred_type=<CredentialType.ROLE: 'role'>, " \
            "cred_path='test_role/test_session', aws_role_name='test_role', " \
            "aws_role_session_name='test_session')"


def test_aws_user_identity(user_identity):
    assert user_identity.aws_identity == 'arn:aws:iam::123456789012:user/test_user'
    assert user_identity.aws_userid == 'AIDEXAMPLE'
    assert user_identity.cred_type.value == 'user'
    assert user_identity.aws_account_id == '123456789012'
    assert user_identity.aws_user_name == 'test_user'

def test_aws_user_identity_repr(user_identity):
    assert repr(user_identity) == "AwsUserIdentity(aws_userid='AIDEXAMPLE', " \
            "aws_account_id='123456789012', cred_type=<CredentialType.USER: 'user'>, " \
            "cred_path='test_user', aws_user_name='test_user')"
    