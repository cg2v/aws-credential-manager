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
    value = {
        'AccessKeyId': creds.aws_access_key_id,
        'SecretAccessKey': creds.aws_secret_access_key
    }
    if creds.aws_session_token:
        value['SessionToken'] = creds.aws_session_token
    print(json.dumps(value))
