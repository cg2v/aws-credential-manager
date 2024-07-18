from pytest import raises
from multicred.base_objects import CredentialType
from multicred.utils import parse_principal

def test_parse_principal_role():
    arn = 'arn:aws:iam::123456789012:role/role-name'
    identity_key = parse_principal(arn)
    assert identity_key.cred_type == CredentialType.ROLE
    assert identity_key.account_id == '123456789012'
    assert identity_key.name == 'role-name'
def test_parse_principal_role_withpath():
    arn = 'arn:aws:iam::123456789012:role/path/role-name'
    identity_key = parse_principal(arn)
    assert identity_key.cred_type == CredentialType.ROLE
    assert identity_key.account_id == '123456789012'
    assert identity_key.name == 'role-name'
def test_parse_principal_user():
    arn = 'arn:aws:iam::123456789012:user/user-name'
    identity_key = parse_principal(arn)
    assert identity_key.cred_type == CredentialType.USER
    assert identity_key.account_id == '123456789012'
    assert identity_key.name == 'user-name'
def test_parse_principal_assumed_role():
    arn = 'arn:aws:iam::123456789012:assumed-role/role-name/session-name'
    identity_key = parse_principal(arn)
    assert identity_key.cred_type == CredentialType.ROLE
    assert identity_key.account_id == '123456789012'
    assert identity_key.name == 'role-name'
def test_parse_principal_unknown_named():
    arn = 'arn:aws:iam::123456789012:unknown/unknown-name'
    identity_key = parse_principal(arn)
    assert identity_key.cred_type == CredentialType.UNKNOWN
    assert identity_key.account_id == '123456789012'
    assert identity_key.name == 'unknown-name'
def test_parse_principal_unknown_unnamed():
    arn = 'arn:aws:iam::123456789012:unknown'
    identity_key = parse_principal(arn)
    assert identity_key.cred_type == CredentialType.UNKNOWN
    assert identity_key.account_id == '123456789012'
    assert identity_key.name == 'unknown'
def test_parse_principal_invalid_arn():
    arn = 'arn:aws:iam::123456789012:invalid'
    with raises(ValueError):
        parse_principal(arn)
def test_parse_principal_invalid_resource():
    arn = 'arn:aws:iam::123456789012:invalid/invalid-name'
    with raises(ValueError):
        parse_principal(arn)
def test_parse_principal_root():
    # root credentials are explicitly not supported
    arn = 'arn:aws:iam::123456789012:root'
    with raises(ValueError):
        parse_principal(arn)
