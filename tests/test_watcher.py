import os
import time
from configparser import ConfigParser
from unittest.mock import MagicMock, patch

from moto import mock_aws

from multicred.dbstorage import DBStorage
from multicred.watcher import (
    CredentialFileEventHandler,
    build_watched_files,
    run_watcher,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_credentials_file(path: str, access_key: str, secret_key: str,
                            session_token: str | None = None, profile: str = 'default'):
    """Write a minimal INI-style credentials file."""
    config = ConfigParser()
    config[profile] = {
        'aws_access_key_id': access_key,
        'aws_secret_access_key': secret_key,
    }
    if session_token:
        config[profile]['aws_session_token'] = session_token
    with open(path, 'w') as fh:
        config.write(fh)


# ---------------------------------------------------------------------------
# build_watched_files
# ---------------------------------------------------------------------------

def test_build_watched_files_absolute(tmp_path):
    files = [str(tmp_path / 'a.ini'), str(tmp_path / 'b.ini')]
    result = build_watched_files(files, 'default')
    for f in files:
        assert os.path.abspath(f) in result
        assert result[os.path.abspath(f)] == 'default'


def test_build_watched_files_relative(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = build_watched_files(['creds.ini'], 'myprofile')
    expected = os.path.abspath(str(tmp_path / 'creds.ini'))
    assert expected in result
    assert result[expected] == 'myprofile'


# ---------------------------------------------------------------------------
# CredentialFileEventHandler – unit-level (mocked do_import)
# ---------------------------------------------------------------------------

class FakeFileSystemEvent:
    """Minimal stand-in for a watchdog FileSystemEvent."""
    def __init__(self, src_path: str, is_directory: bool = False):
        self.src_path = src_path
        self.is_directory = is_directory


def test_handler_on_modified_calls_import(tmp_path):
    cred_file = str(tmp_path / 'creds.ini')
    watched = {os.path.abspath(cred_file): 'default'}
    storage = MagicMock()

    with patch('multicred.watcher.do_import') as mock_import:
        handler = CredentialFileEventHandler(watched, storage)
        handler.on_modified(FakeFileSystemEvent(cred_file))
        mock_import.assert_called_once_with(os.path.abspath(cred_file), storage, 'default')


def test_handler_on_created_calls_import(tmp_path):
    cred_file = str(tmp_path / 'creds.ini')
    watched = {os.path.abspath(cred_file): 'default'}
    storage = MagicMock()

    with patch('multicred.watcher.do_import') as mock_import:
        handler = CredentialFileEventHandler(watched, storage)
        handler.on_created(FakeFileSystemEvent(cred_file))
        mock_import.assert_called_once_with(os.path.abspath(cred_file), storage, 'default')


def test_handler_ignores_unwatched_file(tmp_path):
    cred_file = str(tmp_path / 'creds.ini')
    other_file = str(tmp_path / 'other.ini')
    watched = {os.path.abspath(cred_file): 'default'}
    storage = MagicMock()

    with patch('multicred.watcher.do_import') as mock_import:
        handler = CredentialFileEventHandler(watched, storage)
        handler.on_modified(FakeFileSystemEvent(other_file))
        mock_import.assert_not_called()


def test_handler_ignores_directory_events(tmp_path):
    cred_file = str(tmp_path / 'creds.ini')
    watched = {os.path.abspath(cred_file): 'default'}
    storage = MagicMock()

    with patch('multicred.watcher.do_import') as mock_import:
        handler = CredentialFileEventHandler(watched, storage)
        handler.on_modified(FakeFileSystemEvent(cred_file, is_directory=True))
        mock_import.assert_not_called()


def test_handler_multiple_files_different_profiles(tmp_path):
    file_a = os.path.abspath(str(tmp_path / 'a.ini'))
    file_b = os.path.abspath(str(tmp_path / 'b.ini'))
    watched = {file_a: 'profile_a', file_b: 'profile_b'}
    storage = MagicMock()

    with patch('multicred.watcher.do_import') as mock_import:
        handler = CredentialFileEventHandler(watched, storage)
        handler.on_modified(FakeFileSystemEvent(file_a))
        handler.on_modified(FakeFileSystemEvent(file_b))
        assert mock_import.call_count == 2
        mock_import.assert_any_call(file_a, storage, 'profile_a')
        mock_import.assert_any_call(file_b, storage, 'profile_b')


# ---------------------------------------------------------------------------
# run_watcher – integration-level using real Observer but mocked do_import
# ---------------------------------------------------------------------------

@mock_aws
def test_run_watcher_detects_file_change(tmp_path):
    """Write a credentials file, start the watcher, modify the file, and
    assert that do_import is called with the correct arguments."""
    import threading
    import boto3

    # Obtain real STS credentials so they pass the is_valid check inside do_import.
    client = boto3.client('sts')
    response = client.assume_role(
        RoleArn='arn:aws:iam::123456789012:role/test_role',
        RoleSessionName='watcher_session',
    )
    access_key = response['Credentials']['AccessKeyId']
    secret_key = response['Credentials']['SecretAccessKey']
    token = response['Credentials']['SessionToken']

    cred_file = str(tmp_path / 'creds.ini')
    write_credentials_file(cred_file, access_key, secret_key, token)

    storage = DBStorage('sqlite:///:memory:')
    watched = build_watched_files([cred_file], 'default')

    imported_event = threading.Event()
    imported_files: list[str] = []

    def fake_import(filename, iolayer, profile):
        imported_files.append(filename)
        imported_event.set()

    with patch('multicred.watcher.do_import', side_effect=fake_import):
        def _run():
            run_watcher(watched, storage, poll_interval=0.05)

        t = threading.Thread(target=_run, daemon=True)
        t.start()

        # Give the observer a moment to start before writing the file change.
        time.sleep(0.2)

        # Modify the file to trigger an event.
        write_credentials_file(cred_file, access_key, secret_key, token)

        # Wait up to 5 seconds for the import callback to fire.
        assert imported_event.wait(timeout=5), "do_import was not called within the expected time"

    assert os.path.abspath(cred_file) in imported_files
