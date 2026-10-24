"""Small per-user file mailbox used when socket-based CLI IPC is unavailable.

Only a small allowlist of commands is accepted. Requests and acknowledgements
are atomically written so the elevated GUI and its normal-integrity launcher
do not need to share a TCP port or a Windows named-pipe ACL.
"""
import json
import os
import time
import uuid


ALLOWED_COMMANDS = frozenset({"PING", "BACKGROUND", "READY"})


def mailbox_directory():
    """Return a mailbox directory shared by the current Windows user."""
    root = os.environ.get("LOCALAPPDATA")
    if not root:
        root = os.path.join(os.path.expanduser("~"), "AppData", "Local")
    return os.path.join(root, "elmoCut", "ipc")


def _atomic_write_json(path, payload):
    """Write JSON to a temporary sibling and atomically publish it."""
    temporary = path + ".tmp"
    try:
        with open(temporary, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.remove(temporary)
        except FileNotFoundError:
            pass


def _remove_if_present(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def send_mailbox_command(command, timeout=2.0, directory=None):
    """Submit a CLI command and wait for the GUI's acknowledgement.

    Returns True only when the GUI acknowledged that the command was accepted.
    The caller is responsible for checking that an application instance exists
    before using this fallback transport.
    """
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"Unsupported mailbox command: {command!r}")

    directory = directory or mailbox_directory()
    os.makedirs(directory, exist_ok=True)

    request_id = f"{os.getpid()}-{uuid.uuid4().hex}"
    stem = os.path.join(directory, f"request-{request_id}")
    request_path = stem + ".json"
    acknowledgement_path = stem + ".ack"

    _atomic_write_json(request_path, {"id": request_id, "command": command})
    deadline = time.monotonic() + max(0.0, float(timeout))
    try:
        while True:
            try:
                with open(acknowledgement_path, "r", encoding="utf-8") as stream:
                    acknowledgement = json.load(stream)
                if acknowledgement.get("id") == request_id:
                    return bool(acknowledgement.get("ok"))
            except (FileNotFoundError, json.JSONDecodeError, OSError):
                pass

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.05, remaining))
    finally:
        _remove_if_present(request_path)
        _remove_if_present(acknowledgement_path)
        _remove_if_present(request_path + ".tmp")
        _remove_if_present(acknowledgement_path + ".tmp")


def service_mailbox(command_handler, directory=None, logger=None):
    """Process pending requests once; intended to be called by a GUI timer.

    The handler returns truthy only when it accepted a command. A malformed or
    unsupported request is discarded instead of blocking the mailbox forever.
    """
    directory = directory or mailbox_directory()
    os.makedirs(directory, exist_ok=True)
    processed = 0

    try:
        names = sorted(os.listdir(directory))
    except OSError as exc:
        if logger:
            logger(f"Could not list command mailbox: {exc!r}")
        return processed

    for name in names:
        if not (name.startswith("request-") and name.endswith(".json")):
            continue

        request_path = os.path.join(directory, name)
        stem, _ = os.path.splitext(request_path)
        acknowledgement_path = stem + ".ack"

        try:
            with open(request_path, "r", encoding="utf-8") as stream:
                request = json.load(stream)
        except FileNotFoundError:
            continue
        except (OSError, json.JSONDecodeError) as exc:
            if logger:
                logger(f"Discarding unreadable command-mailbox request {name}: {exc!r}")
            _remove_if_present(request_path)
            continue

        request_id = request.get("id") if isinstance(request, dict) else None
        command = request.get("command") if isinstance(request, dict) else None
        if (
            not isinstance(request_id, str)
            or not request_id
            or not isinstance(command, str)
            or command not in ALLOWED_COMMANDS
        ):
            if logger:
                logger(f"Discarding invalid command-mailbox request {name}")
            _remove_if_present(request_path)
            continue

        try:
            accepted = bool(command_handler(command))
            acknowledgement = {
                "id": request_id,
                "ok": accepted,
                "message": "accepted" if accepted else "rejected",
            }
        except Exception as exc:
            if logger:
                logger(f"Command-mailbox handler failed for {command}: {exc!r}")
            acknowledgement = {
                "id": request_id,
                "ok": False,
                "message": f"{type(exc).__name__}: {exc}",
            }

        try:
            _atomic_write_json(acknowledgement_path, acknowledgement)
            _remove_if_present(request_path)
            processed += 1
        except OSError as exc:
            if logger:
                logger(f"Could not acknowledge command-mailbox request {name}: {exc!r}")

    return processed
