#!python
# -*- coding: utf-8 -*-
import argparse
import io
import json
import chardet

from multicred import get_storage
from multicred import resolver
from multicred import credentials

PARSER = argparse.ArgumentParser(description='Test multicred storage')
COMMANDS=PARSER.add_mutually_exclusive_group(required=True)
COMMANDS.add_argument('--add', action='store_true', help='Add a credential')
COMMANDS.add_argument('--get', action='store_true', help='Get a credential')
COMMANDS.add_argument('--test', action='store_true', help='Set then get the same credential')
PARSER.add_argument('--key', help='Access key')
PARSER.add_argument('--arn', help='ARN')
FILEARG = PARSER.add_mutually_exclusive_group()
FILEARG.add_argument('--json-cred', help='JSON Credential', type=argparse.FileType('rb'))
FILEARG.add_argument('--ini-cred', help='INI Credential', type=argparse.FileType('rb'))

ARGS = PARSER.parse_args()

def dump_credential(cred: credentials.Credentials | None) -> None:
    if cred is None:
        print('Credential not found')
    else:
        print(cred)
        print(cred.aws_identity)
        print(cred.is_valid)
        print(cred.aws_access_key_id)
        print(cred.aws_secret_access_key)
        print(cred.aws_session_token)
        print(cred.aws_identity.aws_identity)
        print(cred.aws_identity.aws_userid)
        print(cred.aws_identity.cred_type)
        print(cred.aws_identity.aws_account_id)

def get_textstream(file: io.BufferedReader) -> io.TextIOWrapper:
    '''Convert a binary file to a text stream'''
    detected = chardet.detect(file.read())
    file.seek(0)
    return io.TextIOWrapper(file, encoding=detected['encoding'])

STORAGE = get_storage('sqlite:///:memory:')
RESOLVER = resolver.StorageBasedResolver(STORAGE)
if ARGS.add or ARGS.test:
    if ARGS.json_cred:
        TEXTIO = get_textstream(ARGS.json_cred)
        JSON_DATA = json.load(TEXTIO)
        CRED = credentials.Credentials(
            aws_access_key_id=JSON_DATA['Credentials']['AccessKeyId'],
            aws_secret_access_key=JSON_DATA['Credentials']['SecretAccessKey'],
            aws_session_token=JSON_DATA['Credentials']['SessionToken'])
        if not CRED.is_valid:
            userid_parts = JSON_DATA["AssumedRoleUser"]["AssumedRoleId"].split(":")
            CRED.aws_identity = credentials.AwsRoleIdentity(
                aws_identity=JSON_DATA['AssumedRoleUser']['Arn'],
                aws_userid=userid_parts[0],
                aws_role_session_name=userid_parts[1])
    elif ARGS.ini_cred:
        TEXTIO = get_textstream(ARGS.ini_cred)
        CRED = credentials.Credentials.from_shared_credentials_file(TEXTIO)
    else:
        raise ValueError('No credential source')
    print(CRED)
    ARN = CRED.aws_identity.aws_identity
    ACCOUNT = CRED.aws_identity.aws_account_id
    ROLE_NM = CRED.aws_identity._resource_components[1]

if ARGS.add:
    STORAGE.import_credentials(CRED)

elif ARGS.get:
    if ARGS.key:
        CRED = RESOLVER.get_credentials_by_key(ARGS.key)
    elif ARGS.arn:
        CRED = RESOLVER.get_credentials_by_arn(ARGS.arn)
    else:
        raise ValueError('No credential source')
    dump_credential(CRED)
elif ARGS.test:
    STORAGE.import_credentials(CRED)
    CRED = RESOLVER.get_credentials_by_key(CRED.aws_access_key_id)
    dump_credential(CRED)
    assert RESOLVER.get_credentials_by_arn(ARN) == CRED
    assert RESOLVER.get_credentials_by_account_and_role_name(ACCOUNT, ROLE_NM) == CRED