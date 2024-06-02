import argparse
import sys
import os
import io
import chardet

from . import get_storage
from . import credentials

def get_textstream(file: io.BufferedReader) -> io.TextIOWrapper:
    '''Convert a binary file to a text stream'''
    detected = chardet.detect(file.read())
    file.seek(0)
    return io.TextIOWrapper(file, encoding=detected['encoding'])

DB_PATH = os.path.expanduser('~/.aws/multicred.db')
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

    rawfile = open(args.cred_file, 'rb')
    textfile = get_textstream(rawfile)
    creds = credentials.Credentials.from_shared_credentials_file(
        textfile, profile_name=args.profile)

    if args.debug:
        print(creds)
        sys.exit(0)
    iolayer = get_storage(DB_PATH)
    iolayer.import_credentials(creds)

if __name__ == '__main__':
    main()
