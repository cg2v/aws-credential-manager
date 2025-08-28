import argparse
import sys
import os
import json

from sqlalchemy.exc import SQLAlchemyError

from . import get_resolver

DB_PATH = 'sqlite:///' +  os.path.expanduser('~/.aws/multicred.db')
def main():
    parser = argparse.ArgumentParser(description='Get AWS credentials from database')
    fetchgroup = parser.add_mutually_exclusive_group(required=True)
    fetchgroup.add_argument('--arn', help='ARN of the identity to fetch credentials for')
    fetchgroup.add_argument('--access-key', help='Access key to fetch credentials for')
    fetchgroup.add_argument('--account', help='Account number to fetch credentials for')
    parser.add_argument('--role', help='Role name to fetch credentials for')
    parser.add_argument('--debug', help='Enable debug logging', action='store_true')
    shellgroup = parser.add_mutually_exclusive_group(required=False)
    shellgroup.add_argument('--shell', '--bash', help='Output bash variables instead of JSON',
            default=False, action='store_true')
    shellgroup.add_argument('--csh', help='Output CSH variables instead of JSON',
            default=False, action='store_true')
    args = parser.parse_args()

    if args.account is not None and args.role is None:
       parser.error("--role is required with --account")

    iolayer = get_resolver(DB_PATH)
    try:
        if args.arn:
            creds = iolayer.get_credentials_by_arn(args.arn)
        elif args.access_key:
            creds = iolayer.get_credentials_by_key(args.access_key)
        elif args.account and args.role:
            creds = iolayer.get_credentials_by_account_and_role_name(args.account, args.role)
        else:
            raise ValueError('Unknown fetch method')
    except (ValueError, SQLAlchemyError):
        creds = None
    if creds is None:
        print('No credentials found', file=sys.stderr)
        sys.exit(1)
    if args.shell or args.csh:
        if args.csh:
            fmtenv='setenv {0} {1}'
        else:
            fmtenv='export {0}={1}'
        print(fmtenv.format('AWS_ACCESS_KEY_ID', creds.aws_access_key_id))
        print(fmtenv.format('AWS_SECRET_ACCESS_KEY', creds.aws_secret_access_key))
        if creds.aws_session_token:
            print(fmtenv.format('AWS_SESSION_TOKEN', creds.aws_session_token))
    value = {
        'Version': 1,
        'AccessKeyId': creds.aws_access_key_id,
        'SecretAccessKey': creds.aws_secret_access_key
    }
    if creds.aws_session_token:
        value['SessionToken'] = creds.aws_session_token
    print(json.dumps(value))
