from .base_objects import CredentialType, IdentityKey

def parse_principal(arn: str) -> IdentityKey:
    """Parse an ARN and return an IdentityHandle object."""
    if not arn.startswith('arn:aws:'):
        raise ValueError('Invalid ARN')
    elements = arn.split(':')
    if len(elements) != 6:
        raise ValueError('Invalid ARN')
    resource = elements[5].split('/')
    # maybe root also?
    if resource[0] not in ['user', 'role', 'assumed-role', 'unknown']:
        raise ValueError('Invalid principal ARN')
    cred_type = CredentialType[resource[0].upper().replace('-', '_')]
    account_id = elements[4]
    if resource[0] == 'assumed-role':
        # first resource is the role name, second is the session name
        name = resource[1]
    else:
        name = resource[-1]
    return IdentityKey(cred_type, account_id, name)
