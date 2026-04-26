"""Tests for the multicred.watcher module."""
from unittest.mock import MagicMock, patch

import pytest

from multicred.base_objects import MultiCredError
from multicred.credentials import MissingCredentialsError
from multicred.watcher import _get_mtime, do_watch


# ---------------------------------------------------------------------------
# _get_mtime helpers
# ---------------------------------------------------------------------------

def test_get_mtime_existing_file(tmp_path):
    f = tmp_path / 'creds'
    f.write_text('[default]\naws_access_key_id=A\n')
    mtime = _get_mtime(str(f))
    assert mtime is not None
    assert mtime == pytest.approx(f.stat().st_mtime)


def test_get_mtime_missing_file(tmp_path):
    assert _get_mtime(str(tmp_path / 'nonexistent')) is None


# ---------------------------------------------------------------------------
# do_watch – single iteration helpers
# ---------------------------------------------------------------------------

def _make_storage():
    return MagicMock()


# ---------------------------------------------------------------------------
# do_watch behaviour tests
# ---------------------------------------------------------------------------

def test_do_watch_imports_on_change(tmp_path):
    """do_watch calls do_import when a file's mtime changes."""
    cred_file = tmp_path / 'credentials'
    cred_file.write_text('[default]\naws_access_key_id=A\n')
    path = str(cred_file)
    storage = _make_storage()

    original_mtime = cred_file.stat().st_mtime
    new_mtime = original_mtime + 1.0

    with patch('multicred.watcher._get_mtime') as mock_mtime, \
         patch('multicred.watcher.do_import') as mock_import, \
         patch('multicred.watcher.time.sleep', side_effect=[None, StopIteration()]):
        # First call (during initialisation) returns original mtime;
        # second call (inside the loop) returns a newer mtime.
        mock_mtime.side_effect = [original_mtime, new_mtime]
        try:
            do_watch([path], storage, 'default', 0.0)
        except StopIteration:
            pass

    mock_import.assert_called_once_with(path, storage, 'default')


def test_do_watch_no_import_when_unchanged(tmp_path):
    """do_watch does NOT call do_import when mtime stays the same."""
    cred_file = tmp_path / 'credentials'
    cred_file.write_text('[default]\naws_access_key_id=A\n')
    path = str(cred_file)
    storage = _make_storage()
    mtime = cred_file.stat().st_mtime

    with patch('multicred.watcher._get_mtime', return_value=mtime), \
         patch('multicred.watcher.do_import') as mock_import, \
         patch('multicred.watcher.time.sleep', side_effect=[None, StopIteration()]):
        try:
            do_watch([path], storage, 'default', 0.0)
        except StopIteration:
            pass

    mock_import.assert_not_called()


def test_do_watch_handles_file_gone(tmp_path):
    """do_watch logs a warning and continues when a watched file disappears."""
    cred_file = tmp_path / 'credentials'
    cred_file.write_text('[default]\naws_access_key_id=A\n')
    path = str(cred_file)
    storage = _make_storage()
    original_mtime = cred_file.stat().st_mtime

    with patch('multicred.watcher._get_mtime') as mock_mtime, \
         patch('multicred.watcher.do_import') as mock_import, \
         patch('multicred.watcher.time.sleep', side_effect=[None, StopIteration()]):
        # File disappears on the loop iteration
        mock_mtime.side_effect = [original_mtime, None]
        try:
            do_watch([path], storage, 'default', 0.0)
        except StopIteration:
            pass

    mock_import.assert_not_called()


def test_do_watch_handles_import_oserror(tmp_path):
    """do_watch logs and continues when do_import raises OSError."""
    cred_file = tmp_path / 'credentials'
    cred_file.write_text('[default]\naws_access_key_id=A\n')
    path = str(cred_file)
    storage = _make_storage()
    original_mtime = cred_file.stat().st_mtime

    with patch('multicred.watcher._get_mtime') as mock_mtime, \
         patch('multicred.watcher.do_import', side_effect=OSError('disk error')), \
         patch('multicred.watcher.time.sleep', side_effect=[None, StopIteration()]):
        mock_mtime.side_effect = [original_mtime, original_mtime + 1]
        try:
            do_watch([path], storage, 'default', 0.0)
        except StopIteration:
            pass
    # reaching here means the exception was caught and did not propagate


def test_do_watch_handles_missing_credentials_error(tmp_path):
    """do_watch logs and continues when do_import raises MissingCredentialsError."""
    cred_file = tmp_path / 'credentials'
    cred_file.write_text('[default]\naws_access_key_id=A\n')
    path = str(cred_file)
    storage = _make_storage()
    original_mtime = cred_file.stat().st_mtime

    with patch('multicred.watcher._get_mtime') as mock_mtime, \
         patch('multicred.watcher.do_import',
               side_effect=MissingCredentialsError('bad creds')), \
         patch('multicred.watcher.time.sleep', side_effect=[None, StopIteration()]):
        mock_mtime.side_effect = [original_mtime, original_mtime + 1]
        try:
            do_watch([path], storage, 'default', 0.0)
        except StopIteration:
            pass


def test_do_watch_handles_multicred_error(tmp_path):
    """do_watch logs and continues when do_import raises MultiCredError."""
    cred_file = tmp_path / 'credentials'
    cred_file.write_text('[default]\naws_access_key_id=A\n')
    path = str(cred_file)
    storage = _make_storage()
    original_mtime = cred_file.stat().st_mtime

    with patch('multicred.watcher._get_mtime') as mock_mtime, \
         patch('multicred.watcher.do_import',
               side_effect=MultiCredError('inactive')), \
         patch('multicred.watcher.time.sleep', side_effect=[None, StopIteration()]):
        mock_mtime.side_effect = [original_mtime, original_mtime + 1]
        try:
            do_watch([path], storage, 'default', 0.0)
        except StopIteration:
            pass


def test_do_watch_multiple_paths(tmp_path):
    """do_watch watches multiple paths and imports each that changes."""
    path_a = str(tmp_path / 'creds_a')
    path_b = str(tmp_path / 'creds_b')
    storage = _make_storage()
    mtime_a = 100.0
    mtime_b = 200.0

    with patch('multicred.watcher._get_mtime') as mock_mtime, \
         patch('multicred.watcher.do_import') as mock_import, \
         patch('multicred.watcher.time.sleep', side_effect=[None, StopIteration()]):
        # Initialisation: a=100, b=200
        # Loop iteration: a=101 (changed), b=200 (unchanged)
        mock_mtime.side_effect = [mtime_a, mtime_b, mtime_a + 1, mtime_b]
        try:
            do_watch([path_a, path_b], storage, 'default', 0.0)
        except StopIteration:
            pass

    mock_import.assert_called_once_with(path_a, storage, 'default')
