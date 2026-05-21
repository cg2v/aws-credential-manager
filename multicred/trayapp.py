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
from dataclasses import dataclass
import logging
import os
import queue
import sys
import threading
from typing import Any
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import winreg
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver
import pystray
from PIL import Image, ImageDraw

from . import get_storage
from . import watcher

logger = logging.getLogger(__name__)

_MUTEX_NAME = 'Global\\MulticredTrayApp'
_AUTOSTART_KEY = r'Software\Microsoft\Windows\CurrentVersion\Run'
_AUTOSTART_VALUE = 'MulticredTray'
_SETTINGS_KEY = r'Software\Multicred\TrayApp'
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
# Settings dataclass and registry helpers
# ---------------------------------------------------------------------------

@dataclass
class TraySettings:
    """Application settings stored in Windows registry."""
    db_path: str
    profile: str
    debounce_seconds: float
    watched_paths: list[str]


def load_settings() -> TraySettings:
    """Load settings from registry, creating key with defaults if missing."""
    default_db_path = 'sqlite:///' + os.path.expanduser('~/.aws/multicred.db')
    defaults = TraySettings(
        db_path=default_db_path,
        profile='default',
        debounce_seconds=5.0,
        watched_paths=[],
    )

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _SETTINGS_KEY) as key:
            db_path = winreg.QueryValueEx(key, 'DatabasePath')[0]
            profile = winreg.QueryValueEx(key, 'Profile')[0]
            debounce_seconds = float(winreg.QueryValueEx(key, 'DebounceSeconds')[0])
            watched_paths = list(winreg.QueryValueEx(key, 'WatchedPaths')[0]) if winreg.QueryValueEx(key, 'WatchedPaths')[0] else []
            return TraySettings(
                db_path=db_path,
                profile=profile,
                debounce_seconds=debounce_seconds,
                watched_paths=watched_paths,
            )
    except FileNotFoundError:
        # Key doesn't exist; create it with defaults and return defaults
        save_settings(defaults)
        return defaults
    except (ValueError, OSError) as exc:
        logger.warning(f'Failed to load settings from registry: {exc}. Using defaults.')
        return defaults


def save_settings(settings: TraySettings) -> None:
    """Save settings to registry, creating key if needed."""
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _SETTINGS_KEY) as key:
            winreg.SetValueEx(key, 'DatabasePath', 0, winreg.REG_SZ, settings.db_path)
            winreg.SetValueEx(key, 'Profile', 0, winreg.REG_SZ, settings.profile)
            winreg.SetValueEx(key, 'DebounceSeconds', 0, winreg.REG_SZ, str(settings.debounce_seconds))
            # REG_MULTI_SZ is type 7
            winreg.SetValueEx(key, 'WatchedPaths', 0, 7, settings.watched_paths)
    except OSError as exc:
        logger.error(f'Failed to save settings to registry: {exc}')


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


# ---------------------------------------------------------------------------
# Settings pane
# ---------------------------------------------------------------------------

class SettingsPane:
    """Tkinter settings dialog for configuring tray app settings."""

    def __init__(self, root: tk.Tk, app: CredentialTrayApp) -> None:
        self._root = root
        self._app = app
        self._window = tk.Toplevel(root)
        self._window.title('MulticredTray — Settings')
        self._window.geometry('600x500')
        self._window.protocol('WM_DELETE_WINDOW', self.hide)
        self._window.withdraw()  # start hidden

        # Build the form
        frame = tk.Frame(self._window, padx=10, pady=10)
        frame.pack(fill='both', expand=True)

        # Database Path
        tk.Label(frame, text='Database Path:', font=('Arial', 10, 'bold')).grid(
            row=0, column=0, sticky='w', pady=(5, 2))
        db_frame = tk.Frame(frame)
        db_frame.grid(row=1, column=0, columnspan=2, sticky='ew', pady=(0, 10))
        db_frame.columnconfigure(0, weight=1)
        self._db_path_var = tk.StringVar()
        self._db_path_entry = tk.Entry(db_frame, textvariable=self._db_path_var)
        self._db_path_entry.pack(side='left', fill='x', expand=True, padx=(0, 5))
        tk.Button(db_frame, text='Browse…', command=self._browse_db).pack(side='left')

        # Profile
        tk.Label(frame, text='Profile:', font=('Arial', 10, 'bold')).grid(
            row=2, column=0, sticky='w', pady=(5, 2))
        self._profile_var = tk.StringVar()
        tk.Entry(frame, textvariable=self._profile_var).grid(
            row=3, column=0, columnspan=2, sticky='ew', pady=(0, 10))

        # Debounce Seconds
        tk.Label(frame, text='Debounce Delay (seconds):', font=('Arial', 10, 'bold')).grid(
            row=4, column=0, sticky='w', pady=(5, 2))
        self._debounce_var = tk.StringVar()
        tk.Entry(frame, textvariable=self._debounce_var).grid(
            row=5, column=0, columnspan=2, sticky='ew', pady=(0, 10))

        # Watched Paths
        tk.Label(frame, text='Watched Credential Files:', font=('Arial', 10, 'bold')).grid(
            row=6, column=0, columnspan=2, sticky='w', pady=(5, 2))
        paths_frame = tk.Frame(frame)
        paths_frame.grid(row=7, column=0, columnspan=2, sticky='nsew', pady=(0, 10))
        paths_frame.columnconfigure(0, weight=1)
        paths_frame.rowconfigure(0, weight=1)

        scrollbar = tk.Scrollbar(paths_frame)
        scrollbar.pack(side='right', fill='y')
        self._paths_listbox = tk.Listbox(paths_frame, yscrollcommand=scrollbar.set)
        self._paths_listbox.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self._paths_listbox.yview)

        # Add/Remove buttons for paths
        buttons_frame = tk.Frame(frame)
        buttons_frame.grid(row=8, column=0, columnspan=2, sticky='ew', pady=(0, 10))
        tk.Button(buttons_frame, text='Add Path…', command=self._add_path).pack(side='left', padx=(0, 5))
        tk.Button(buttons_frame, text='Remove Selected', command=self._remove_path).pack(side='left')

        # Save / Cancel buttons
        button_frame = tk.Frame(frame)
        button_frame.grid(row=9, column=0, columnspan=2, sticky='e', pady=(10, 0))
        tk.Button(button_frame, text='Save', command=self._save).pack(side='left', padx=(0, 5))
        tk.Button(button_frame, text='Cancel', command=self._cancel).pack(side='left')

        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(7, weight=1)

    # ------------------------------------------------------------------

    def show(self) -> None:
        """Show the settings pane, reloading current settings from registry."""
        self._load()
        self._window.deiconify()
        self._window.lift()

    def hide(self) -> None:
        """Hide the settings pane without saving."""
        self._window.withdraw()

    def _load(self) -> None:
        """Populate fields from current registry settings."""
        try:
            settings = load_settings()
            self._db_path_var.set(settings.db_path)
            self._profile_var.set(settings.profile)
            self._debounce_var.set(str(settings.debounce_seconds))
            self._paths_listbox.delete(0, tk.END)
            for path in settings.watched_paths:
                self._paths_listbox.insert(tk.END, path)
        except Exception as exc:
            messagebox.showerror('Settings Error', f'Failed to load settings: {exc}')

    def _save(self) -> None:
        """Validate, save settings to registry, and apply to app."""
        try:
            # Validate debounce
            debounce_seconds = float(self._debounce_var.get())
            if debounce_seconds <= 0:
                messagebox.showwarning('Invalid Input', 'Debounce delay must be positive.')
                return

            # Get paths from listbox
            watched_paths = list(self._paths_listbox.get(0, tk.END))

            # Create new settings
            new_settings = TraySettings(
                db_path=self._db_path_var.get(),
                profile=self._profile_var.get(),
                debounce_seconds=debounce_seconds,
                watched_paths=watched_paths,
            )

            # Validate DB path (basic check)
            if not new_settings.db_path:
                messagebox.showwarning('Invalid Input', 'Database path cannot be empty.')
                return

            # Save to registry
            save_settings(new_settings)

            # Apply settings to app
            self._app.apply_settings(new_settings)

            messagebox.showinfo('Settings', 'Settings saved successfully.')
            self.hide()
        except ValueError:
            messagebox.showwarning('Invalid Input', 'Debounce delay must be a valid number.')
        except Exception as exc:
            messagebox.showerror('Settings Error', f'Failed to save settings: {exc}')

    def _cancel(self) -> None:
        """Close without saving."""
        self.hide()

    def _browse_db(self) -> None:
        """Open a file dialog to select or create a database file."""
        file_path = filedialog.asksaveasfilename(
            title='Select or create database file',
            defaultextension='.db',
            filetypes=[('SQLite Database', '*.db'), ('All Files', '*.*')],
        )
        if file_path:
            # Convert to sqlite:// URI format
            uri = 'sqlite:///' + file_path.replace('\\', '/')
            self._db_path_var.set(uri)

    def _add_path(self) -> None:
        """Open a file dialog to add a credential file to the watched paths."""
        file_path = filedialog.askopenfilename(
            title='Select a credential file to monitor',
            filetypes=[('All Files', '*.*')],
        )
        if file_path:
            # Check if already in list
            current_paths = list(self._paths_listbox.get(0, tk.END))
            if file_path not in current_paths:
                self._paths_listbox.insert(tk.END, file_path)

    def _remove_path(self) -> None:
        """Remove the selected path from the listbox."""
        selection = self._paths_listbox.curselection()
        if selection:
            self._paths_listbox.delete(selection[0])


class WrappedCredentialsFileEventHandler(watcher.CredentialFileEventHandler):

    def __init__(self, *args, **kwargs):
        self.logfunc = kwargs.pop('logfunc', lambda msg: None)
        self.statusfunc = kwargs.pop('statusfunc', lambda status: None)
        super().__init__(*args, **kwargs)

    def log(self, message: str, *args):
        self.logfunc(message % args if args else message)

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

    def __init__(self, settings: TraySettings | None = None) -> None:
        """Initialize the app with settings. If settings is None, load from registry."""
        if settings is None:
            settings = load_settings()
        self._settings = settings

        # Create storage from settings
        self._storage = get_storage(settings.db_path)

        # Build watched files map from settings
        self._paths = watcher.build_watched_files(settings.watched_paths, settings.profile)
        self._profile = settings.profile
        self._debounce_delay = settings.debounce_seconds
        self._has_paths = bool(settings.watched_paths)  # Track if we have paths

        self._stop_event = threading.Event()

        self._log_queue: queue.Queue[str] = queue.Queue()
        # Start paused if no paths provided; otherwise start watching
        self._status = _STATUS_PAUSED if not self._has_paths else _STATUS_WATCHING
        self._log_window: LogWindow | None = None
        self._settings_pane: SettingsPane | None = None
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
        self._settings_pane = SettingsPane(self._root, self)

        self._icon = pystray.Icon(
            'MulticredTray',
            icon=_create_icon_image(self._status),
            title=_STATUS_TOOLTIPS[self._status],
            menu=self._create_menu(),
        )

        # Only start observing if we have paths
        if self._has_paths:
            self._observer = Observer()
            self.start_watching(self._observer)
        else:
            self._log('No credential files to watch. App is paused. Enable watching via the menu once paths are configured.')

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
            pystray.MenuItem('Settings…', self._on_settings),
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

    def _on_settings(self, icon=None, item=None) -> None:
        if self._root and self._settings_pane:
            self._root.after(0, self._settings_pane.show)

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
            if not self._has_paths:
                self._log('Cannot resume watching: no credential files configured.')
                return
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

    def apply_settings(self, new_settings: TraySettings) -> None:
        """Apply new settings: update storage, paths, and observer as needed."""
        try:
            # Check if DB path changed; recreate storage if so
            if new_settings.db_path != self._settings.db_path:
                self._storage = get_storage(new_settings.db_path)
                self._log(f'Database path updated: {new_settings.db_path}')

            # Check if watched paths or profile changed
            paths_changed = new_settings.watched_paths != self._settings.watched_paths
            profile_changed = new_settings.profile != self._settings.profile
            debounce_changed = new_settings.debounce_seconds != self._settings.debounce_seconds

            if paths_changed or profile_changed or debounce_changed:
                # Stop existing observer if running
                if self._observer is not None:
                    self._observer.stop()
                    self._observer.join()
                    self._observer = None

                # Update internal state from new settings
                self._settings = new_settings
                self._profile = new_settings.profile
                self._debounce_delay = new_settings.debounce_seconds
                self._paths = watcher.build_watched_files(new_settings.watched_paths, new_settings.profile)
                self._has_paths = bool(new_settings.watched_paths)

                # Start observer if we have paths
                if self._has_paths:
                    self._observer = Observer()
                    self.start_watching(self._observer)
                    self._set_status(_STATUS_WATCHING)
                    self._log('Watching resumed with updated settings.')
                else:
                    self._set_status(_STATUS_PAUSED)
                    self._log('No credential files configured. App is now paused.')
            else:
                # Only DB path changed (or nothing changed at all)
                self._settings = new_settings
        except Exception as exc:
            self._log(f'Error applying settings: {exc}')
            messagebox.showerror('Settings Error', f'Failed to apply settings: {exc}')

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
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s',
    )

    app = CredentialTrayApp()
    app.start()
