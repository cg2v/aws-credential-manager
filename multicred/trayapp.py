"""Windows background process with system tray icon, menu, and log window.

Incorporates the credential-file watcher (replacing multicred-watch as the
recommended way to run the daemon).  Provides:

  - Tray icon whose colour reflects daemon state (green/yellow/red)
  - Right-click menu: Show/hide log, Statistics, Pause/resume, Auto-start, Quit
  - Scrollable log window (hidden at startup)
  - Single-instance guard via Windows named mutex
  - Auto-start toggle via HKCU Run registry key

Threading model
~~~~~~~~~~~~~~~
  Main thread  : tkinter mainloop (hidden root window)
  pystray      : icon.run_detached() runs in its own OS thread
  Watcher      : daemon thread; controlled via threading.Event objects
  Log comms    : queue.Queue drained by root.after(200, ...) on main thread
"""

from __future__ import annotations

import argparse
import ctypes
import datetime
import logging
import os
import queue
import sys
import threading
from typing import Any
import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
import winreg
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver
import pystray
from PIL import Image, ImageDraw

from . import get_storage
from . import watcher
from .interfaces import Storage

logger = logging.getLogger(__name__)

DB_PATH = 'sqlite:///' + os.path.expanduser('~/.aws/multicred.db')

_MUTEX_NAME = 'Global\\MulticredTrayApp'
_AUTOSTART_KEY = r'Software\Microsoft\Windows\CurrentVersion\Run'
_AUTOSTART_VALUE = 'MulticredTray'
_ICON_SIZE = 64
_LOG_QUEUE_POLL_MS = 200

# Tray icon status values
_STATUS_WATCHING = 'watching'   # green
_STATUS_PAUSED = 'paused'       # yellow
_STATUS_ERROR = 'error'         # red

_STATUS_COLOURS = {
    _STATUS_WATCHING: (76, 175, 80),    # material green 500
    _STATUS_PAUSED: (255, 193, 7),      # material amber 500
    _STATUS_ERROR: (244, 67, 54),       # material red 500
}

_STATUS_TOOLTIPS = {
    _STATUS_WATCHING: 'MulticredTray — watching',
    _STATUS_PAUSED: 'MulticredTray — paused',
    _STATUS_ERROR: 'MulticredTray — last import failed',
}

# ---------------------------------------------------------------------------
# Single-instance guard
# ---------------------------------------------------------------------------

def _check_single_instance() -> None:
    """Exit if another instance is already running (Windows named mutex)."""
    ERROR_ALREADY_EXISTS = 183
    handle = ctypes.windll.kernel32.CreateMutexW(None, True, _MUTEX_NAME)
    if ctypes.windll.kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
        print('MulticredTray is already running.', file=sys.stderr)
        sys.exit(1)
    # Keep the handle alive for the process lifetime (don't close it).
    # Store on the module so it is not garbage-collected.
    _check_single_instance._mutex_handle = handle


# ---------------------------------------------------------------------------
# Auto-start helpers
# ---------------------------------------------------------------------------

def _autostart_command() -> str:
    """Return the command string stored in the registry run key."""
    # Reconstruct the original command line: python executable + module flag + args.
    args = [sys.executable, '-m', 'multicred.trayapp'] + sys.argv[1:]
    # Quote arguments that contain spaces.
    quoted = []
    for a in args:
        quoted.append(f'"{a}"' if ' ' in a else a)
    return ' '.join(quoted)


def _is_autostart_enabled() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _AUTOSTART_KEY) as key:
            winreg.QueryValueEx(key, _AUTOSTART_VALUE)
        return True
    except FileNotFoundError:
        return False


def _set_autostart(enable: bool) -> None:
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, _AUTOSTART_KEY, access=winreg.KEY_SET_VALUE
    ) as key:
        if enable:
            winreg.SetValueEx(key, _AUTOSTART_VALUE, 0, winreg.REG_SZ, _autostart_command())
        else:
            try:
                winreg.DeleteValue(key, _AUTOSTART_VALUE)
            except FileNotFoundError:
                pass


# ---------------------------------------------------------------------------
# Icon image generation
# ---------------------------------------------------------------------------

def _create_icon_image(status: str) -> Image.Image:
    """Return a PIL Image with a coloured circle for *status*."""
    colour = _STATUS_COLOURS.get(status, _STATUS_COLOURS[_STATUS_WATCHING])
    img = Image.new('RGBA', (_ICON_SIZE, _ICON_SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    margin = 4
    draw.ellipse(
        [margin, margin, _ICON_SIZE - margin, _ICON_SIZE - margin],
        fill=colour + (255,),
    )
    return img


# ---------------------------------------------------------------------------
# Log window
# ---------------------------------------------------------------------------

class LogWindow:
    """Toggleable tkinter log window.  Must only be created on the main thread."""

    def __init__(self, root: tk.Tk) -> None:
        self._root = root
        self._window = tk.Toplevel(root)
        self._window.title('MulticredTray — Log')
        self._window.geometry('700x300')
        self._window.protocol('WM_DELETE_WINDOW', self.hide)

        self._text = ScrolledText(self._window, state='disabled', wrap='word',
                                  font=('Consolas', 9))
        self._text.pack(fill='both', expand=True)
        self._window.withdraw()  # start hidden

    # ------------------------------------------------------------------
    def show(self) -> None:
        self._window.deiconify()
        self._window.lift()

    def hide(self) -> None:
        self._window.withdraw()

    def toggle(self) -> None:
        if self._window.state() == 'withdrawn':
            self.show()
        else:
            self.hide()

    def append(self, message: str) -> None:
        """Append *message* to the log.  Must be called on the main thread."""
        self._text.configure(state='normal')
        self._text.insert(tk.END, message + '\n')
        self._text.configure(state='disabled')
        self._text.see(tk.END)

class WrappedCredentialsFileEventHandler(watcher.CredentialFileEventHandler):

    def __init__(self, *args, **kwargs):
        self.logfunc = kwargs.pop('logfunc', lambda msg: None)
        self.statusfunc = kwargs.pop('statusfunc', lambda status: None)
        super().__init__(*args, **kwargs)

    def log(self, message: str, *args):
        self.logfunc(message.format(*args))

    error = log

    def _do_import(self, abs_path: str, profile: str) -> bool:
        rv = super()._do_import(abs_path, profile)
        if rv:
            self.statusfunc(_STATUS_WATCHING)
        else:
            self.statusfunc(_STATUS_ERROR)
        return rv


# ---------------------------------------------------------------------------
# Main application class
# ---------------------------------------------------------------------------

class CredentialTrayApp:
    """Windows system-tray daemon that watches credential files and imports them."""

    def __init__(self, paths: list[str], storage: Storage, profile: str,
                 debounce_delay: float = 5.0) -> None:
        self._paths = watcher.build_watched_files(paths, profile)
        self._storage = storage
        self._profile = profile
        self._debounce_delay = debounce_delay

        self._stop_event = threading.Event()

        self._log_queue: queue.Queue[str] = queue.Queue()
        self._status = _STATUS_WATCHING
        self._log_window: LogWindow | None = None
        self._icon: Any | None = None
        self._root: tk.Tk | None = None  # tkinter root; set in start()
        self._observer: BaseObserver | None = None  # watchdog observer; set in start()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Check single instance, build GUI, start threads, run mainloop."""
        _check_single_instance()

        self._root = tk.Tk()
        self._root.withdraw()  # hide the root window; we only want the tray
        self._root.title('MulticredTray')

        self._log_window = LogWindow(self._root)

        self._icon = pystray.Icon(
            'MulticredTray',
            icon=_create_icon_image(_STATUS_WATCHING),
            title=_STATUS_TOOLTIPS[_STATUS_WATCHING],
            menu=self._create_menu(),
        )

        self._observer = Observer()
        self.start_watching(self._observer)

        # pystray runs in its own thread; we keep tkinter on the main thread.
        self._icon.run_detached()

        # Start polling the log queue on the main thread.
        self._root.after(_LOG_QUEUE_POLL_MS, self._poll_log_queue)

        try:
            self._root.mainloop()
        finally:
            self._stop_event.set()
            if self._icon:
                self._icon.stop()

    # ------------------------------------------------------------------
    # Tray menu
    # ------------------------------------------------------------------

    def _create_menu(self) -> pystray.Menu:
        return pystray.Menu(
            pystray.MenuItem('Show / hide log', self._on_show_hide_log),
            pystray.MenuItem('Statistics…', self._on_stats),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                'Pause watching',
                self._on_pause_resume,
                checked=lambda item: self._observer is None,
            ),
            pystray.MenuItem(
                'Start automatically at login',
                self._on_toggle_autostart,
                checked=lambda item: _is_autostart_enabled(),
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Quit', self._on_quit),
        )

    # ------------------------------------------------------------------
    # Menu callbacks (called from pystray thread)
    # ------------------------------------------------------------------

    def _on_show_hide_log(self, icon=None, item=None) -> None:
        if self._root and self._log_window:
            self._root.after(0, self._log_window.toggle)

    def _on_stats(self, icon=None, item=None) -> None:
        if self._root:
            self._root.after(0, self._show_stats_dialog)

    def _show_stats_dialog(self) -> None:
        try:
            stats = self._storage.get_statistics()
            msg = (
                f'Identities:    {stats.total_identities}\n'
                f'Credentials:   {stats.total_credentials}\n'
                f'Roles:         {stats.total_roles}\n'
                f'Accounts:      {stats.total_accounts}\n'
                f'Max creds/id:  {stats.max_credentials_per_identity}'
            )
        except Exception as exc:
            msg = f'Could not retrieve statistics:\n{exc}'
        messagebox.showinfo('MulticredTray — Statistics', msg)

    def _on_pause_resume(self, icon=None, item=None) -> None:
        if self._observer is None:
            self._observer = Observer()
            self.start_watching(self._observer)
            self._set_status(_STATUS_WATCHING)
            self._log('Watching resumed.')
        else:
            self._observer.stop()
            self._observer.join()
            self._observer = None
            self._set_status(_STATUS_PAUSED)
            self._log('Watching paused.')

    def _on_toggle_autostart(self, icon=None, item=None) -> None:
        enabled = _is_autostart_enabled()
        try:
            _set_autostart(not enabled)
        except OSError as exc:
            self._log(f'Auto-start toggle failed: {exc}')

    def _on_quit(self, icon=None, item=None) -> None:
        self._stop_event.set()
        if self._icon:
            self._icon.stop()
        if self._root:
            self._root.after(0, self._root.quit)

    def start_watching(self, observer: BaseObserver) -> None:
        handler = WrappedCredentialsFileEventHandler(self._paths, self._storage,
                                         debounce_delay=self._debounce_delay,
                                         logfunc=self._log,
                                         statusfunc=self._set_status)
        watched_dirs: set[str] = set()
        for abs_path in self._paths:
            dir_path = os.path.dirname(abs_path) or '.'
            if dir_path not in watched_dirs:
                observer.schedule(handler, dir_path, recursive=False)
                watched_dirs.add(dir_path)

        observer.start()
        self._log(f'Watching {len(self._paths)} file(s) for changes. Right-click the tray icon for options.')
    # ------------------------------------------------------------------
    # Status / icon helpers
    # ------------------------------------------------------------------

    def _set_status(self, status: str) -> None:
        if self._status == status:
            return
        self._status = status
        if self._icon:
            self._icon.icon = _create_icon_image(status)
            self._icon.title = _STATUS_TOOLTIPS[status]

    # ------------------------------------------------------------------
    # Log helpers (thread-safe)
    # ------------------------------------------------------------------

    def _log(self, message: str) -> None:
        """Queue *message* for display in the log window (any thread)."""
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        self._log_queue.put(f'[{ts}] {message}')
        logger.debug(message)

    def _poll_log_queue(self) -> None:
        """Drain the log queue and append messages to the log window."""
        try:
            while True:
                msg = self._log_queue.get_nowait()
                if self._log_window:
                    self._log_window.append(msg)
        except queue.Empty:
            pass
        if self._root:
            self._root.after(_LOG_QUEUE_POLL_MS, self._poll_log_queue)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            'Run MulticredTray — a Windows background process that watches '
            'credential files for changes and imports them automatically.'
        )
    )
    parser.add_argument('--profile', default='default',
                        help='Profile name to import credentials from')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    parser.add_argument('--debounce', metavar='SECONDS', type=float,
                        default=watcher._DEFAULT_DEBOUNCE_DELAY,
                        help='Seconds to wait after a change before importing '
                             f'(default: {watcher._DEFAULT_DEBOUNCE_DELAY})')
    parser.add_argument('paths', nargs='+', help='Credential file(s) to watch')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s',
    )

    storage = get_storage(DB_PATH)
    app = CredentialTrayApp(args.paths, storage, args.profile, args.debounce)
    app.start()
