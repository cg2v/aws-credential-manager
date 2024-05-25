#!python
# -*- coding: utf-8 -*-
import argparse
import io
import json
import configparser
import chardet

from multicred import storage
from multicred import credentials

PARSER = argparse.ArgumentParser(description='Test multicred storage')
COMMANDS=PARSER.add_mutually_exclusive_group(required=True)
COMMANDS.add_argument('--add', action='store_true', help='Add a credential')
COMMANDS.add_argument('--get', action='store_true', help='Get a credential')
PARSER.add_argument('--key', help='Access key')
PARSER.add_argument('--arn', help='ARN')
FILEARG = PARSER.add_mutually_exclusive_group()
FILEARG.add_argument('--json-cred', help='JSON Credential', type=argparse.FileType('rb'))
FILEARG.add_argument('--ini-cred', help='INI Credential', type=argparse.FileType('rb'))

ARGS = PARSER.parse_args()

def get_textstream(file: io.BufferedReader) -> io.TextIOWrapper:
    '''Convert a binary file to a text stream'''
    detected = chardet.detect(file.read())
    file.seek(0)
    return io.TextIOWrapper(file, encoding=detected['encoding'])

STORAGE = storage.Storage("sqlite://")
if ARGS.add:
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
        FILEPARSER = configparser.ConfigParser()
        FILEPARSER.read_file(TEXTIO)
        DEFSECT = FILEPARSER.sections()[0]
        CRED = credentials.Credentials(
            aws_access_key_id=FILEPARSER[DEFSECT]['aws_access_key_id'],
            aws_secret_access_key=FILEPARSER[DEFSECT]['aws_secret_access_key'],
            aws_session_token=FILEPARSER[DEFSECT]['aws_session_token'])
    else:
        raise ValueError('No credential source')
    print(CRED)
    STORAGE.import_credentials(CRED)

elif ARGS.get:
    if ARGS.key:
        CRED = STORAGE.get_credentials_by_key(ARGS.key)
    elif ARGS.arn:
        CRED = STORAGE.get_credentials_by_arn(ARGS.arn)
    else:
        raise ValueError('No credential source')
    if CRED is None:
        print('Credential not found')
    else:
        print(CRED)
        print(CRED.aws_identity)
        print(CRED.is_valid)
        print(CRED.aws_access_key_id)
        print(CRED.aws_secret_access_key)
        print(CRED.aws_session_token)
        print(CRED.aws_identity.aws_identity)
        print(CRED.aws_identity.aws_userid)
        print(CRED.aws_identity.cred_type)
        print(CRED.aws_identity.aws_account_id)
