from multicred.credentials import Credentials, AwsRoleIdentity, AwsUserIdentity

creds = Credentials.from_shared_credentials_file('C:/Users/chas3/Downloads/assumed_creds')
print(creds)

if creds.aws_identity.cred_type == 'role':
    assert isinstance(creds.aws_identity, AwsRoleIdentity)
    print(creds.aws_identity.aws_role_name)
else:
    assert isinstance(creds.aws_identity, AwsUserIdentity)
    print(creds.aws_identity.aws_user_name)