"""Daemon that watches credential files for changes and imports them automatically."""
import argparse
import logging
import os
import sys
import time

from . import get_storage
from .base_objects import MultiCredError
from . import credentials
from .importer import do_import
from .interfaces import Storage

logger = logging.getLogger(__name__)

DB_PATH = 'sqlite:///' + os.path.expanduser('~/.aws/multicred.db')


def _get_mtime(path: str) -> float | None:
    """Return the modification time of a file, or None if inaccessible."""
    try:
        return os.stat(path).st_mtime
    except OSError:
        return None


def do_watch(paths: list[str], storage: Storage, profile: str, interval: float = 5.0):
    """Poll *paths* for modifications and import credentials whenever a file changes.

    Runs indefinitely until interrupted (KeyboardInterrupt / SIGTERM).
    """
    mtimes: dict[str, float | None] = {path: _get_mtime(path) for path in paths}
    logger.info('Watching %d path(s) with %.1fs polling interval', len(paths), interval)

    while True:
        time.sleep(interval)
        for path in paths:
            mtime = _get_mtime(path)
            if mtime == mtimes[path]:
                continue
            mtimes[path] = mtime
            if mtime is None:
                logger.warning('Path no longer accessible: %s', path)
                continue
            logger.info('Change detected in %s, importing credentials', path)
            try:
                do_import(path, storage, profile)
                logger.info('Successfully imported credentials from %s', path)
            except OSError as e:
                logger.warning('Error reading %s: %s', path, e)
            except credentials.MissingCredentialsError as e:
                logger.warning('Missing credentials in %s: %s', path, e)
            except MultiCredError as e:
                logger.warning('Could not import credentials from %s: %s', path, e)


def main():
    parser = argparse.ArgumentParser(
        description='Watch credential files for changes and import them automatically')
    parser.add_argument('--profile', help='Profile name to import credentials from',
                        default='default')
    parser.add_argument('--interval', help='Polling interval in seconds',
                        type=float, default=5.0, metavar='SECONDS')
    parser.add_argument('--debug', help='Enable debug logging', action='store_true')
    parser.add_argument('paths', nargs='+', help='Credential file(s) to watch')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s',
    )

    storage = get_storage(DB_PATH)
    try:
        do_watch(args.paths, storage, args.profile, args.interval)
    except KeyboardInterrupt:
        logger.info('Interrupted, exiting')
        sys.exit(0)


if __name__ == '__main__':
    main()
