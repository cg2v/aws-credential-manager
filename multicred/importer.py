import argparse
import sys
import os
import io
import chardet

from . import get_storage
from . import credentials
from .interfaces import Storage

def get_textstream(file: io.BufferedReader) -> io.TextIOWrapper:
    '''Convert a binary file to a text stream'''
    detected = chardet.detect(file.read())
    file.seek(0)
    return io.TextIOWrapper(file, encoding=detected['encoding'])

def do_import(filename: str, iolayer: Storage, profile: str):
    '''Import credentials from a file'''
    with open(filename, 'rb') as rawfile:
        textfile = get_textstream(rawfile)
        creds = credentials.Credentials.from_shared_credentials_file(
            textfile, profile_name=profile)
    iolayer.import_credentials(creds)

DB_PATH = 'sqlite:///' + os.path.expanduser('~/.aws/multicred.db')
def main():
    parser = argparse.ArgumentParser(description='Import AWS credentials')
    parser.add_argument('--profile', help='Profile name to import credentials from',
                        default='default')
    parser.add_argument('--debug', help='Enable debug logging', action='store_true')
    parser.add_argument('cred_file', help='File containing credentials',
                        default=os.environ.get('AWS_SHARED_CREDENTIALS_FILE', None))
    args = parser.parse_args()

    if not args.cred_file:
        print('No credentials file specified', file=sys.stderr)
        sys.exit(1)

    do_import(args.cred_file, get_storage(DB_PATH), args.profile)

if __name__ == '__main__':
    main()
