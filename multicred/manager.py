import argparse
import sys
import os
import boto3

from . import get_storage
from . import credentials
from .interfaces import Storage
from .importer import do_import

DB_PATH = 'sqlite:///' + os.path.expanduser('~/.aws/multicred.db')
def build_parser():
    parser = argparse.ArgumentParser(description='Manage AWS credentials storage')
    parser.add_argument('--debug', help='Enable debug logging', action='store_true')
    subparsers = parser.add_subparsers(dest='subcommand', required=True)
    import_parser = subparsers.add_parser('import', help='Import AWS credentials')
    import_parser.add_argument('--profile', help='Profile name to import credentials from',
                               default='default')
    import_parser.add_argument('cred_file', help='File containing credentials',
                                 default=os.environ.get('AWS_SHARED_CREDENTIALS_FILE', None))
    link_parser = subparsers.add_parser('link', help='Link two AWS identities')
    parent_account_group = link_parser.add_argument_group("source credentials")
    parent_account_group.add_argument('--parent-account', help='Account number of the parent identity',
                                      required=True)
    parent_account_group.add_argument('--parent-role', help='Role name of the parent identity',
                                        required=True)
    link_parser.add_argument('--role-arn', help='ARN of role to assume',
                             required=True)
    unlink_parser = subparsers.add_parser('unlink', help='Unlink an AWS identity')
    unlink_parser.add_argument('--arn', help='ARN of the identity to unlink')
    delete_cred_parser = subparsers.add_parser('delete', help='Delete a set of AWS credentials')
    delete_cred_parser.add_argument('--access-key', help='Access key to delete', required=True)
    purge_account_parser = subparsers.add_parser('purge', help='Delete all credentials for an identity')
    purge_account_parser.add_argument('--account', help='Account number of the identity to delete',
                                        required=True)
    purge_account_parser.add_argument('--role-name', help='Role name to delete',
                                        required=True)
    #subparsers.add_parser('purge-all', help='Delete AWS credentials')
    return parser

def do_unlink(args: argparse.Namespace, iolayer: Storage):
    identity = iolayer.get_identity_by_arn(args.arn)
    if identity is None:
        print('Identity not found', file=sys.stderr)
        sys.exit(1)
    iolayer.remove_identity_relationship(identity)

def do_delete(args: argparse.Namespace, iolayer: Storage):
    if args.access_key:
        iolayer.delete_credentials_by_key(args.access_key)
    elif args.account and args.role_name:
        identity = iolayer.get_identity_by_account_and_role_name(args.account, args.role_name)
        if identity is None:
            print('Identity not found', file=sys.stderr)
            sys.exit(1)
        iolayer.purge_identity_credentials(identity)

def do_link(args: argparse.Namespace, iolayer: Storage):
    parent_identity = iolayer.get_identity_by_account_and_role_name(
        args.parent_account, args.parent_role)
    if parent_identity is None:
        print('Parent identity not found', file=sys.stderr)
        sys.exit(1)
    parent_creds = iolayer.get_identity_credentials(parent_identity)
    if parent_creds is None:
        print('Parent credentials not found', file=sys.stderr)
        sys.exit(1)
    if not parent_creds.is_valid:
        print('Cannot assume role with invalid credentials', file=sys.stderr)
        sys.exit(1)
    client = boto3.client('sts', **parent_creds.get_boto3_credentials())
    response = client.assume_role(
        RoleArn=args.role_arn,
        RoleSessionName=parent_identity.name)
    creds = credentials.Credentials(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])
    iolayer.import_credentials(creds)
    target_identity = iolayer.get_identity_by_arn(creds.aws_identity.aws_identity)
    if target_identity is None:
        print('Identity in target creds not found', file=sys.stderr)
        sys.exit(1)
    existing_relationship = iolayer.get_parent_identity(target_identity)
    if existing_relationship[0] is not None:
        if existing_relationship[0].arn == parent_identity.arn:
            print('Identity already linked', file=sys.stderr)
        else:
            print('Identity already linked to a different parent', file=sys.stderr)
        sys.exit(1)

    iolayer.construct_identity_relationship(creds, parent_creds, args.role_arn)
def main():
    parser = build_parser()
    args = parser.parse_args()
    iolayer = get_storage(DB_PATH)
    if args.subcommand == 'import':
        if not args.cred_file:
            print('No credentials file specified', file=sys.stderr)
            sys.exit(1)
        do_import(args.cred_file, iolayer, args.profile)
    elif args.subcommand == 'link':
        do_link(args, iolayer)
    elif args.subcommand == 'unlink':
        do_unlink(args, iolayer)
    elif args.subcommand == 'delete' or args.subcommand == 'purge':
        do_delete(args, iolayer)
    else:
        raise ValueError('Unknown subcommand')

if __name__ == '__main__':
    main()
