"""Tests for multicred.trayapp.

All GUI and OS interactions (pystray, tkinter, ctypes, winreg) are mocked so
that the test suite runs headlessly in CI.
"""
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Minimal stub modules for imports that are absent in CI (pystray, PIL, winreg,
# ctypes.windll).  These are injected before the module is imported so that
# the import itself succeeds.
# ---------------------------------------------------------------------------

def _make_pystray_stub():
    pystray = types.ModuleType('pystray')

    class MenuItem:
        SEPARATOR = object()

        def __init__(self, text, action=None, checked=None):
            self.text = text
            self.action = action
            self.checked = checked

    class Menu:
        SEPARATOR = object()

        def __init__(self, *items):
            self.items = items

    class Icon:
        def __init__(self, name, icon=None, title=None, menu=None):
            self.name = name
            self.icon = icon
            self.title = title
            self.menu = menu
            self._stopped = False

        def run_detached(self):
            pass

        def stop(self):
            self._stopped = True

    pystray.MenuItem = MenuItem
    pystray.Menu = Menu
    pystray.Icon = Icon
    return pystray


def _make_pil_stub():
    pil = types.ModuleType('PIL')
    image_mod = types.ModuleType('PIL.Image')
    draw_mod = types.ModuleType('PIL.ImageDraw')

    class FakeImage:
        def __init__(self, mode, size, color=None):
            self.mode = mode
            self.size = size

    class FakeDraw:
        def __init__(self, img):
            self._img = img

        def ellipse(self, xy, fill=None):
            pass

    image_mod.new = lambda mode, size, color=None: FakeImage(mode, size, color)
    draw_mod.Draw = FakeDraw

    pil.Image = image_mod
    pil.ImageDraw = draw_mod
    sys.modules['PIL'] = pil
    sys.modules['PIL.Image'] = image_mod
    sys.modules['PIL.ImageDraw'] = draw_mod
    return pil


# Install stubs before importing trayapp.
if 'pystray' not in sys.modules:
    sys.modules['pystray'] = _make_pystray_stub()
_make_pil_stub()

# winreg may not exist on non-Windows CI; provide a stub.
if 'winreg' not in sys.modules:
    winreg_stub = types.ModuleType('winreg')
    winreg_stub.HKEY_CURRENT_USER = 0x80000001
    winreg_stub.KEY_SET_VALUE = 2
    winreg_stub.KEY_READ = 0x20019
    winreg_stub.REG_SZ = 1
    winreg_stub.REG_MULTI_SZ = 7
    winreg_stub.OpenKey = MagicMock()
    winreg_stub.CreateKey = MagicMock()
    winreg_stub.QueryValueEx = MagicMock()
    winreg_stub.SetValueEx = MagicMock()
    winreg_stub.DeleteValue = MagicMock()
    sys.modules['winreg'] = winreg_stub

# Stub ctypes.windll so _check_single_instance works without a real mutex.
import ctypes as _ctypes
if not hasattr(_ctypes, 'windll'):
    windll_stub = MagicMock()
    _ctypes.windll = windll_stub

# Stub tkinter sub-modules that require a display / root window.
# These are imported directly by trayapp (from tkinter import filedialog, messagebox)
# and will fail on headless Linux if left as real tkinter objects.
import tkinter as _tkinter_module
_tkinter_module.filedialog = MagicMock()
_tkinter_module.filedialog.asksaveasfilename = MagicMock(return_value='')
_tkinter_module.filedialog.askopenfilename = MagicMock(return_value='')

import tkinter.filedialog as _filedialog_module
_filedialog_module.asksaveasfilename = MagicMock(return_value='')
_filedialog_module.askopenfilename = MagicMock(return_value='')

# Stub tkinter.messagebox so showwarning/showerror/showinfo never open a real Tk window.
import tkinter.messagebox as _messagebox_module
_messagebox_module.showwarning = MagicMock()
_messagebox_module.showinfo = MagicMock()
_messagebox_module.showerror = MagicMock()
_messagebox_module.askyesno = MagicMock(return_value=True)

from multicred import trayapp  # noqa: E402 — must come after stubs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_storage():
    from multicred.interfaces import Statistics
    storage = MagicMock()
    storage.get_statistics.return_value = Statistics(
        total_identities=2,
        total_credentials=5,
        total_roles=1,
        total_accounts=1,
        max_credentials_per_identity=3,
    )
    return storage


def _make_app_for_testing():
    """Create a CredentialTrayApp instance for testing with mocked storage."""
    settings = trayapp.TraySettings(
        db_path='sqlite:///test.db',
        profile='default',
        debounce_seconds=5.0,
        watched_paths=['/fake/creds'],
    )
    with patch.object(trayapp, 'get_storage', return_value=_make_storage()):
        app = trayapp.CredentialTrayApp(settings=settings)
    return app


# ---------------------------------------------------------------------------
# _check_single_instance
# ---------------------------------------------------------------------------

class TestCheckSingleInstance:
    def test_exits_when_mutex_already_exists(self):
        with patch.object(_ctypes.windll.kernel32, 'CreateMutexW', return_value=1), \
             patch.object(_ctypes.windll.kernel32, 'GetLastError', return_value=183):
            with pytest.raises(SystemExit) as exc_info:
                trayapp._check_single_instance()
            assert exc_info.value.code == 1

    def test_continues_when_no_existing_mutex(self):
        with patch.object(_ctypes.windll.kernel32, 'CreateMutexW', return_value=1), \
             patch.object(_ctypes.windll.kernel32, 'GetLastError', return_value=0):
            # Should not raise
            trayapp._check_single_instance()


# ---------------------------------------------------------------------------
# Auto-start helpers
# ---------------------------------------------------------------------------

class TestAutostart:
    def test_is_autostart_enabled_returns_true_when_key_exists(self):
        import winreg
        mock_key = MagicMock()
        mock_key.__enter__ = lambda s: s
        mock_key.__exit__ = MagicMock(return_value=False)
        with patch.object(winreg, 'OpenKey', return_value=mock_key), \
             patch.object(winreg, 'QueryValueEx', return_value=('cmd', 1)):
            assert trayapp._is_autostart_enabled() is True

    def test_is_autostart_enabled_returns_false_when_key_missing(self):
        import winreg
        with patch.object(winreg, 'OpenKey', side_effect=FileNotFoundError):
            assert trayapp._is_autostart_enabled() is False

    def test_set_autostart_enable_sets_registry_value(self):
        import winreg
        mock_key = MagicMock()
        mock_key.__enter__ = lambda s: s
        mock_key.__exit__ = MagicMock(return_value=False)
        with patch.object(winreg, 'OpenKey', return_value=mock_key), \
             patch.object(winreg, 'SetValueEx') as mock_set:
            trayapp._set_autostart(True)
            mock_set.assert_called_once()
            args = mock_set.call_args[0]
            assert args[1] == trayapp._AUTOSTART_VALUE

    def test_set_autostart_disable_deletes_registry_value(self):
        import winreg
        mock_key = MagicMock()
        mock_key.__enter__ = lambda s: s
        mock_key.__exit__ = MagicMock(return_value=False)
        with patch.object(winreg, 'OpenKey', return_value=mock_key), \
             patch.object(winreg, 'DeleteValue') as mock_del:
            trayapp._set_autostart(False)
            mock_del.assert_called_once_with(mock_key, trayapp._AUTOSTART_VALUE)

    def test_set_autostart_disable_tolerates_missing_value(self):
        import winreg
        mock_key = MagicMock()
        mock_key.__enter__ = lambda s: s
        mock_key.__exit__ = MagicMock(return_value=False)
        with patch.object(winreg, 'OpenKey', return_value=mock_key), \
             patch.object(winreg, 'DeleteValue', side_effect=FileNotFoundError):
            # Should not raise
            trayapp._set_autostart(False)


# ---------------------------------------------------------------------------
# Icon image generation
# ---------------------------------------------------------------------------

class TestCreateIconImage:
    def test_returns_image_for_each_status(self):
        for status in (trayapp._STATUS_WATCHING, trayapp._STATUS_PAUSED,
                       trayapp._STATUS_ERROR):
            img = trayapp._create_icon_image(status)
            assert img is not None

    def test_returns_image_for_unknown_status(self):
        img = trayapp._create_icon_image('unknown')
        assert img is not None


# ---------------------------------------------------------------------------
# WrappedCredentialsFileEventHandler
# ---------------------------------------------------------------------------

class TestWrappedHandler:
    """Tests for WrappedCredentialsFileEventHandler."""

    def _make_handler(self, logfunc=None, statusfunc=None):
        watched = {'/fake/path': 'default'}
        storage = _make_storage()
        return trayapp.WrappedCredentialsFileEventHandler(
            watched, storage, debounce_delay=0,
            logfunc=logfunc or (lambda msg: None),
            statusfunc=statusfunc or (lambda status: None),
        )

    def test_log_routes_to_logfunc(self):
        messages = []
        handler = self._make_handler(logfunc=messages.append)
        handler.log('hello world')
        assert messages == ['hello world']

    def test_log_formats_percent_style_arguments(self):
        messages = []
        handler = self._make_handler(logfunc=messages.append)
        handler.log('imported %s (%s)', 'file', 'default')
        assert messages == ['imported file (default)']

    def test_error_routes_to_logfunc(self):
        messages = []
        handler = self._make_handler(logfunc=messages.append)
        handler.error('something failed')
        assert messages == ['something failed']

    def test_do_import_success_calls_status_watching(self):
        statuses = []
        handler = self._make_handler(statusfunc=statuses.append)
        with patch.object(
            trayapp.watcher.CredentialFileEventHandler, '_do_import', return_value=True
        ):
            handler._do_import('/fake/path', 'default')
        assert statuses == [trayapp._STATUS_WATCHING]

    def test_do_import_failure_calls_status_error(self):
        statuses = []
        handler = self._make_handler(statusfunc=statuses.append)
        with patch.object(
            trayapp.watcher.CredentialFileEventHandler, '_do_import', return_value=False
        ):
            handler._do_import('/fake/path', 'default')
        assert statuses == [trayapp._STATUS_ERROR]


# ---------------------------------------------------------------------------
# CredentialTrayApp — pause / resume
# ---------------------------------------------------------------------------

class TestPauseResume:
    def _make_app(self):
        settings = trayapp.TraySettings(
            db_path='sqlite:///test.db',
            profile='default',
            debounce_seconds=5.0,
            watched_paths=['/fake/creds'],
        )
        with patch.object(trayapp, 'get_storage', return_value=_make_storage()):
            app = trayapp.CredentialTrayApp(settings=settings)
        app._icon = MagicMock()
        return app

    def test_pause_stops_observer_and_sets_status(self):
        app = self._make_app()
        mock_observer = MagicMock()
        app._observer = mock_observer

        app._on_pause_resume()

        mock_observer.stop.assert_called_once()
        mock_observer.join.assert_called_once()
        assert app._observer is None
        assert app._status == trayapp._STATUS_PAUSED

    def test_resume_creates_observer_and_sets_status(self):
        app = self._make_app()
        app._observer = None

        with patch('multicred.trayapp.Observer') as MockObserver, \
             patch.object(app, 'start_watching') as mock_start:
            app._on_pause_resume()
            MockObserver.assert_called_once()
            mock_start.assert_called_once_with(app._observer)

        assert app._status == trayapp._STATUS_WATCHING


# ---------------------------------------------------------------------------
# CredentialTrayApp — log queue
# ---------------------------------------------------------------------------

class TestLogQueue:
    def test_log_enqueues_message(self):
        app = _make_app_for_testing()
        app._log('hello world')
        msg = app._log_queue.get_nowait()
        assert 'hello world' in msg

    def test_poll_log_queue_drains_into_log_window(self):
        app = _make_app_for_testing()

        mock_root = MagicMock()
        mock_log_window = MagicMock()
        app._root = mock_root
        app._log_window = mock_log_window

        app._log_queue.put('[00:00:00] message one')
        app._log_queue.put('[00:00:01] message two')
        app._poll_log_queue()

        assert mock_log_window.append.call_count == 2
        # root.after should be called to reschedule
        mock_root.after.assert_called_once_with(
            trayapp._LOG_QUEUE_POLL_MS, app._poll_log_queue)


# ---------------------------------------------------------------------------
# CredentialTrayApp — quit
# ---------------------------------------------------------------------------

class TestQuit:
    def test_quit_sets_stop_event(self):
        app = _make_app_for_testing()
        app._icon = MagicMock()
        mock_root = MagicMock()
        app._root = mock_root

        app._on_quit()
        assert app._stop_event.is_set()
        app._icon.stop.assert_called_once()
        mock_root.after.assert_called_once()


# ---------------------------------------------------------------------------
# SettingsPane
# ---------------------------------------------------------------------------

class TestSettingsPane:
    def _make_app_mock(self):
        """Create a mock CredentialTrayApp for testing."""
        app = MagicMock()
        app.apply_settings = MagicMock()
        return app

    def _make_tk_mock(self):
        """Create a tk mock where StringVar and Listbox track state correctly."""
        class FakeStringVar:
            def __init__(self):
                self._value = ''
            def get(self):
                return self._value
            def set(self, v):
                self._value = v

        class FakeListbox:
            def __init__(self, *a, **kw):
                self._items = []
            def insert(self, idx, value):
                self._items.append(value)
            def delete(self, start, end=None):
                if end is None:
                    if 0 <= start < len(self._items):
                        del self._items[start]
                else:
                    self._items.clear()
            def get(self, start, end=None):
                return tuple(self._items)
            def curselection(self):
                return ()
            def pack(self, **kw): pass
            def config(self, **kw): pass
            def yview(self, *a): pass

        tk_mock = MagicMock()
        tk_mock.StringVar.side_effect = FakeStringVar
        tk_mock.Listbox.side_effect = FakeListbox
        tk_mock.END = 'end'
        return tk_mock

    def _make_settings(self):
        return trayapp.TraySettings(
            db_path='sqlite:///test.db',
            profile='default',
            debounce_seconds=5.0,
            watched_paths=[],
        )

    def test_settings_pane_save_validates_debounce(self):
        """Test that _save rejects non-positive debounce values."""
        root = MagicMock()
        app = self._make_app_mock()

        with patch.object(trayapp, 'tk', self._make_tk_mock()), \
             patch.object(trayapp, 'load_settings', return_value=self._make_settings()), \
             patch.object(trayapp.messagebox, 'showwarning') as mock_warn:
            pane = trayapp.SettingsPane(root, app)
            pane._debounce_var.set('-1')
            pane._save()
            mock_warn.assert_called()

    def test_settings_pane_save_validates_empty_db_path(self):
        """Test that _save rejects empty database path."""
        root = MagicMock()
        app = self._make_app_mock()

        with patch.object(trayapp, 'tk', self._make_tk_mock()), \
             patch.object(trayapp, 'load_settings', return_value=self._make_settings()), \
             patch.object(trayapp.messagebox, 'showwarning') as mock_warn:
            pane = trayapp.SettingsPane(root, app)
            pane._db_path_var.set('')
            pane._debounce_var.set('5.0')
            pane._save()
            mock_warn.assert_called()

    def test_settings_pane_save_calls_save_settings_and_apply(self):
        """Test that _save calls save_settings and apply_settings on valid input."""
        root = MagicMock()
        app = self._make_app_mock()

        with patch.object(trayapp, 'tk', self._make_tk_mock()), \
             patch.object(trayapp, 'load_settings', return_value=self._make_settings()), \
             patch.object(trayapp, 'save_settings') as mock_save, \
             patch.object(trayapp.messagebox, 'showinfo'):
            pane = trayapp.SettingsPane(root, app)
            pane._db_path_var.set('sqlite:///new.db')
            pane._profile_var.set('default')
            pane._debounce_var.set('3.0')
            pane._save()
            mock_save.assert_called_once()
            app.apply_settings.assert_called_once()

    def test_settings_pane_cancel_hides(self):
        """Test that cancel() hides the pane without saving."""
        root = MagicMock()
        app = self._make_app_mock()

        with patch.object(trayapp, 'tk', self._make_tk_mock()), \
             patch.object(trayapp, 'load_settings', return_value=self._make_settings()):
            pane = trayapp.SettingsPane(root, app)
            pane._window = MagicMock()
            pane._cancel()
            pane._window.withdraw.assert_called_once()


# ---------------------------------------------------------------------------
# main() CLI entry point
# ---------------------------------------------------------------------------

class TestMain:
    def test_main_with_no_args(self):
        """Test that main() creates and starts CredentialTrayApp with no CLI args."""
        with patch.object(trayapp, 'CredentialTrayApp') as mock_app_class, \
             patch.object(trayapp, '_check_single_instance'), \
             patch('sys.argv', ['multicred-tray']):
            mock_app = MagicMock()
            mock_app_class.return_value = mock_app

            trayapp.main()

            # Verify app was created with no arguments (loads from registry)
            mock_app_class.assert_called_once_with()
            # Verify app.start() was called
            mock_app.start.assert_called_once()

    def test_main_with_debug_flag(self):
        """Test that main() accepts --debug flag."""
        with patch.object(trayapp, 'CredentialTrayApp') as mock_app_class, \
             patch.object(trayapp, '_check_single_instance'), \
             patch('sys.argv', ['multicred-tray', '--debug']), \
             patch.object(trayapp.logging, 'basicConfig') as mock_logging:
            mock_app = MagicMock()
            mock_app_class.return_value = mock_app

            trayapp.main()

            # Verify logging was configured at DEBUG level
            call_kwargs = mock_logging.call_args[1]
            assert call_kwargs['level'] == trayapp.logging.DEBUG
            # Verify app was created and started
            mock_app_class.assert_called_once_with()
            mock_app.start.assert_called_once()

    def test_main_without_debug_flag(self):
        """Test that main() configures WARNING logging by default."""
        with patch.object(trayapp, 'CredentialTrayApp') as mock_app_class, \
             patch.object(trayapp, '_check_single_instance'), \
             patch('sys.argv', ['multicred-tray']), \
             patch.object(trayapp.logging, 'basicConfig') as mock_logging:
            mock_app = MagicMock()
            mock_app_class.return_value = mock_app

            trayapp.main()

            # Verify logging was configured at WARNING level
            call_kwargs = mock_logging.call_args[1]
            assert call_kwargs['level'] == trayapp.logging.WARNING
            # Verify app was created and started
            mock_app_class.assert_called_once_with()
            mock_app.start.assert_called_once()
