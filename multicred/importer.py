import argparse
import sys
import os
import io
import chardet

from . import get_storage
from . import credentials
from .interfaces import Storage
from .base_objects import MultiCredError

def get_textstream(file: io.BufferedReader) -> io.TextIOWrapper:
    '''Convert a binary file to a text stream'''
    detected = chardet.detect(file.read())
    file.seek(0)
    return io.TextIOWrapper(file, encoding=detected['encoding'])

def do_import(filename: str, iolayer: Storage, profile: str):
    '''Import credentials from a file.

    Raises:
        OSError: If the file cannot be opened or read.
        credentials.MissingCredentialsError: If the requested profile is absent.
        credentials.ExpiredCredentialsError: If the credentials are not currently active.
        MultiCredError: If the credentials cannot be stored.
    '''
    with open(filename, 'rb') as rawfile:
        textfile = get_textstream(rawfile)
        creds = credentials.Credentials.from_shared_credentials_file(
            textfile, profile_name=profile)
    if not creds.is_valid:
        raise credentials.ExpiredCredentialsError(
            f'Credentials in {filename} are not active, cannot import')
    iolayer.import_credentials(creds)

def do_import_cli(filename: str, iolayer: Storage, profile: str):
    '''Wrapper around do_import for CLI use: prints errors and exits on failure.'''
    try:
        do_import(filename, iolayer, profile)
    except FileNotFoundError:
        print(f'File {filename} not found', file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f'Error reading file: {e}', file=sys.stderr)
        sys.exit(1)
    except credentials.MissingCredentialsError as e:
        print(f'Error reading credentials: {e}', file=sys.stderr)
        sys.exit(1)
    except credentials.ExpiredCredentialsError:
        print('Credentials are not active, cannot import', file=sys.stderr)
        sys.exit(1)
    except MultiCredError as e:
        print(f'Error importing credentials: {e}', file=sys.stderr)
        sys.exit(1)

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

    do_import_cli(args.cred_file, get_storage(DB_PATH), args.profile)

if __name__ == '__main__':
    main()
