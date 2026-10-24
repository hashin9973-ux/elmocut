from os import path, makedirs, rename
from json import dump, load, JSONDecodeError
import ctypes
import winreg
import sys
import threading
import subprocess
from tools.utils import terminal
from constants import *
import os
from os import replace as os_replace

_settings_lock = threading.Lock()

def is_admin():
    """
    Check if current user is Admin
    """
    return bool(ctypes.windll.shell32.IsUserAnAdmin())

def npcap_exists():
    """
    Check for Npcap driver
    """
    return path.exists(NPCAP_PATH)

# A named mutex is a race-safe single-instance guard. Counting tasklist rows
# is unreliable while the unelevated launcher and elevated app overlap.
_INSTANCE_MUTEX_NAME = "Local\\elmoCut.SingleInstance.v2"
_INSTANCE_MUTEX_HANDLE = None
_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_KERNEL32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
_KERNEL32.CreateMutexW.restype = ctypes.c_void_p
_KERNEL32.OpenMutexW.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_wchar_p]
_KERNEL32.OpenMutexW.restype = ctypes.c_void_p
_KERNEL32.CloseHandle.argtypes = [ctypes.c_void_p]
_KERNEL32.CloseHandle.restype = ctypes.c_bool
_KERNEL32.ReleaseMutex.argtypes = [ctypes.c_void_p]
_KERNEL32.ReleaseMutex.restype = ctypes.c_bool
_KERNEL32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
_KERNEL32.WaitForSingleObject.restype = ctypes.c_ulong

_WAIT_OBJECT_0 = 0x00000000
_WAIT_ABANDONED = 0x00000080
_WAIT_TIMEOUT = 0x00000102
_ERROR_ALREADY_EXISTS = 183
_ERROR_FILE_NOT_FOUND = 2
_MUTEX_ACCESS = 0x00100000 | 0x0001  # SYNCHRONIZE | MUTEX_MODIFY_STATE


def single_instance_exists():
    """Return True only when the mutex is actively owned by another process.

    A named mutex handle can exist without an owner. Merely opening it leads to
    false 'already running' reports after a released/abandoned instance.
    """
    handle = _KERNEL32.OpenMutexW(_MUTEX_ACCESS, False, _INSTANCE_MUTEX_NAME)
    if not handle:
        # Access denied means a protected instance may exist; a missing name
        # means no instance guard object exists.
        return ctypes.get_last_error() != _ERROR_FILE_NOT_FOUND

    try:
        wait_result = _KERNEL32.WaitForSingleObject(handle, 0)
        if wait_result == _WAIT_TIMEOUT:
            return True
        if wait_result in (_WAIT_OBJECT_0, _WAIT_ABANDONED):
            _KERNEL32.ReleaseMutex(handle)
            return False
        return True
    finally:
        _KERNEL32.CloseHandle(handle)


def acquire_single_instance():
    """Acquire the named mutex, recovering an existing but currently free object."""
    global _INSTANCE_MUTEX_HANDLE

    # Prevent a stale Win32 error from causing a newly created mutex to be
    # misidentified as a pre-existing instance.
    ctypes.set_last_error(0)
    handle = _KERNEL32.CreateMutexW(None, True, _INSTANCE_MUTEX_NAME)
    last_error = ctypes.get_last_error()
    if not handle:
        raise ctypes.WinError(last_error)

    if last_error == _ERROR_ALREADY_EXISTS:
        # CreateMutex does not grant ownership when the object already exists.
        # Try to acquire it: timeout means another instance really owns it.
        wait_result = _KERNEL32.WaitForSingleObject(handle, 0)
        if wait_result not in (_WAIT_OBJECT_0, _WAIT_ABANDONED):
            _KERNEL32.CloseHandle(handle)
            if wait_result == _WAIT_TIMEOUT:
                return False
            raise ctypes.WinError(ctypes.get_last_error() or 1)

    _INSTANCE_MUTEX_HANDLE = handle
    return True



_LAUNCHER_MUTEX_NAME = "Local\\\\elmoCut.Launcher.v1"
_LAUNCHER_MUTEX_HANDLE = None


def acquire_launcher_mutex():
    """Serialize unelevated launchers while they request an elevated GUI."""
    global _LAUNCHER_MUTEX_HANDLE
    ctypes.set_last_error(0)
    handle = _KERNEL32.CreateMutexW(None, True, _LAUNCHER_MUTEX_NAME)
    last_error = ctypes.get_last_error()
    if not handle:
        raise ctypes.WinError(last_error)
    if last_error == _ERROR_ALREADY_EXISTS:
        wait_result = _KERNEL32.WaitForSingleObject(handle, 0)
        if wait_result not in (_WAIT_OBJECT_0, _WAIT_ABANDONED):
            _KERNEL32.CloseHandle(handle)
            if wait_result == _WAIT_TIMEOUT:
                return False
            raise ctypes.WinError(ctypes.get_last_error() or 1)
    _LAUNCHER_MUTEX_HANDLE = handle
    return True


def release_launcher_mutex():
    """Release the temporary launch lock after the GUI claims its own mutex."""
    global _LAUNCHER_MUTEX_HANDLE
    handle = _LAUNCHER_MUTEX_HANDLE
    if handle:
        _LAUNCHER_MUTEX_HANDLE = None
        _KERNEL32.ReleaseMutex(handle)
        _KERNEL32.CloseHandle(handle)

def release_single_instance():
    """Release ownership before the controlled --restarting hand-off."""
    global _INSTANCE_MUTEX_HANDLE
    handle = _INSTANCE_MUTEX_HANDLE
    if handle:
        _INSTANCE_MUTEX_HANDLE = None
        _KERNEL32.ReleaseMutex(handle)
        _KERNEL32.CloseHandle(handle)

def check_documents_dir():
    """
    Ensure the settings directory exists.
    """
    makedirs(DOCUMENTS_PATH, exist_ok=True)

def _import_settings_unlocked():
    """
    Internal: read settings WITHOUT acquiring the lock.
    Only call this from inside a block that already holds _settings_lock.
    """
    check_documents_dir()
    if not path.exists(SETTINGS_PATH):
        # This function is called while _settings_lock is held. Use the
        # unlocked writer to avoid trying to acquire the same non-reentrant
        # lock a second time during first-run settings creation.
        _export_settings_unlocked()
    with open(SETTINGS_PATH, encoding='utf-8') as settings_file:
        return load(settings_file)

def _export_settings_unlocked(values=None):
    """
    Internal: write settings WITHOUT acquiring the lock, atomically.
    Only call this from inside a block that already holds _settings_lock.
    """
    keys = SETTINGS_KEYS
    values = values if values else SETTINGS_VALS
    json = dict(zip(keys, values))

    tmp_path = SETTINGS_PATH + '.tmp'
    with open(tmp_path, 'w') as f:
        dump(json, f)
    os_replace(tmp_path, SETTINGS_PATH)  # atomic on Windows (same volume)

def import_settings():
    """
    Get stored settings
    """
    with _settings_lock:
        return _import_settings_unlocked()

def export_settings(values=None):
    """
    Store current settings (or create new)
    """
    with _settings_lock:
        _export_settings_unlocked(values)

def set_settings(key, value):
    """
    Update certain setting item (single atomic read-modify-write)
    """
    with _settings_lock:
        s = _import_settings_unlocked()
        s[key] = value
        _export_settings_unlocked(list(s.values()))

def get_settings(key):
    """
    Get certain setting item by key
    """
    with _settings_lock:
        return _import_settings_unlocked()[key]

def repair_settings():
    """
    Rescue elmocut from new settings not found after updates
    """
    original = dict(zip(SETTINGS_KEYS, SETTINGS_VALS))
    
    try:
        s = import_settings()
        for key in s:
            original[key] = s[key]
    except JSONDecodeError:
        pass
        
    export_settings(list(original.values()))

def migrate_settings_file():
    old_exists = path.exists(OLD_SETTINGS_PATH)
    new_exists = path.exists(SETTINGS_PATH)
    if old_exists and not new_exists:
        try:
            makedirs(DOCUMENTS_PATH, exist_ok=True)
            rename(OLD_SETTINGS_PATH, SETTINGS_PATH)
        except Exception as e:
            print(f'Migrating settings error: {e}')
            print('New settings file created instead.')

def add_to_startup(command):
    """
    Register the full quoted Windows command for the current user's startup.
    The value may include arguments such as --background.
    """
    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER,
        HKEY_AUTOSTART_PATH,
        0,
        winreg.KEY_SET_VALUE
    ) as key:
        winreg.SetValueEx(key, 'elmocut', 0, winreg.REG_SZ, command)


def remove_from_startup():
    """Remove elmoCut from the current user's startup registration."""
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            HKEY_AUTOSTART_PATH,
            0,
            winreg.KEY_SET_VALUE
        ) as key:
            try:
                winreg.DeleteValue(key, 'elmocut')
            except FileNotFoundError:
                pass
    except FileNotFoundError:
        pass

def restart_gui_app(_app):
    """
    Relaunch the current executable as a new process, then forcibly
    terminate this one. Passes --restarting so the new instance
    tolerates a brief overlap with the old one during shutdown.
    """
    executable = sys.executable

    args = [a for a in sys.argv if a != executable]
    args = [executable] + args + ['--restarting']

    DETACHED_PROCESS = 0x00000008
    CREATE_NEW_PROCESS_GROUP = 0x00000200

    # Free the single-instance guard before the replacement process starts.
    # Otherwise the new process would correctly mistake this restart for a
    # duplicate launch and refuse to open.
    release_single_instance()

    try:
        subprocess.Popen(
            args,
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception:
        # Restore the guard if relaunching failed, keeping this process usable.
        try:
            acquire_single_instance()
        except Exception:
            pass
        raise

    _app.from_tray = True   # bypass minimize-to-tray on close
    _app.close()

    os._exit(0)