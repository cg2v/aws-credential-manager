import argparse
import logging
import os
import threading
import time

from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent
from watchdog.observers import Observer

from . import get_storage
from .importer import do_import
from .interfaces import Storage

logger = logging.getLogger(__name__)

DB_PATH = 'sqlite:///' + os.path.expanduser('~/.aws/multicred.db')

_DEFAULT_DEBOUNCE_DELAY = 1.0


class CredentialFileEventHandler(FileSystemEventHandler):
    """Watchdog event handler that imports credentials when a watched file changes.

    Multiple filesystem events for the same file within *debounce_delay* seconds are
    collapsed into a single import call, which avoids duplicate imports when an
    application writes a file in several steps (e.g. Chrome's download process).
    """

    def __init__(self, watched_files: dict[str, str], storage: Storage,
                 debounce_delay: float = _DEFAULT_DEBOUNCE_DELAY):
        """
        :param watched_files: mapping of absolute file path -> profile name to import
        :param storage: storage backend to import credentials into
        :param debounce_delay: seconds to wait after the last event before importing
        """
        super().__init__()
        self._watched_files = watched_files
        self._storage = storage
        self._debounce_delay = debounce_delay
        self._pending_timers: dict[str, threading.Timer] = {}
        self._lock = threading.Lock()

    def _schedule_import(self, abs_path: str, profile: str):
        """Cancel any existing debounce timer for *abs_path* and start a new one."""
        with self._lock:
            existing = self._pending_timers.pop(abs_path, None)
            if existing is not None:
                existing.cancel()
            timer = threading.Timer(
                self._debounce_delay, self._do_import, args=(abs_path, profile))
            self._pending_timers[abs_path] = timer
            timer.start()

    def _do_import(self, abs_path: str, profile: str):
        """Execute the import after the debounce window expires."""
        with self._lock:
            self._pending_timers.pop(abs_path, None)
        logger.info('Importing credentials from %s (profile: %s)', abs_path, profile)
        try:
            do_import(abs_path, self._storage, profile)
            logger.info('Successfully imported credentials from %s', abs_path)
        except Exception as e:
            logger.error('Failed to import credentials from %s: %s', abs_path, e)

    def _try_import(self, path: str):
        abs_path = os.path.abspath(path)
        profile = self._watched_files.get(abs_path)
        if profile is None:
            return
        logger.debug('Detected change in %s, scheduling import (profile: %s)',
                     abs_path, profile)
        self._schedule_import(abs_path, profile)

    def on_modified(self, event: FileModifiedEvent):
        if not event.is_directory:
            self._try_import(event.src_path)

    def on_created(self, event: FileCreatedEvent):
        if not event.is_directory:
            self._try_import(event.src_path)


def build_watched_files(paths: list[str], profile: str) -> dict[str, str]:
    """Build a mapping of absolute file paths to the profile to import from them."""
    return {os.path.abspath(p): profile for p in paths}


def run_watcher(watched_files: dict[str, str], storage: Storage,
                poll_interval: float = 1.0,
                debounce_delay: float = _DEFAULT_DEBOUNCE_DELAY):
    """Start file watchers for the given files and block until interrupted."""
    handler = CredentialFileEventHandler(watched_files, storage,
                                         debounce_delay=debounce_delay)
    observer = Observer()

    watched_dirs: set[str] = set()
    for abs_path in watched_files:
        dir_path = os.path.dirname(abs_path) or '.'
        if dir_path not in watched_dirs:
            observer.schedule(handler, dir_path, recursive=False)
            watched_dirs.add(dir_path)

    observer.start()
    logger.info('Watching %d file(s) for changes. Press Ctrl+C to stop.', len(watched_files))
    try:
        while True:
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()


def main():
    parser = argparse.ArgumentParser(
        description='Watch credential files for changes and import them automatically')
    parser.add_argument('--profile', help='Profile name to import credentials from',
                        default='default')
    parser.add_argument('--debug', help='Enable debug logging', action='store_true')
    parser.add_argument('--debounce', metavar='SECONDS', type=float,
                        default=_DEFAULT_DEBOUNCE_DELAY,
                        help='Seconds to wait after a change before importing '
                             f'(default: {_DEFAULT_DEBOUNCE_DELAY})')
    parser.add_argument('cred_files', metavar='cred_file', nargs='+',
                        help='File(s) to watch for credential changes')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s')

    storage = get_storage(DB_PATH)
    watched_files = build_watched_files(args.cred_files, args.profile)
    run_watcher(watched_files, storage, debounce_delay=args.debounce)


if __name__ == '__main__':
    main()
