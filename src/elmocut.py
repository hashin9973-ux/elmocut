import ctypes
import os
import socket
import subprocess
import sys
import time
import traceback


def startup_log(message):
    """Append startup diagnostics to a per-user log, even in windowed builds."""
    try:
        log_root = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local"
        )
        log_dir = os.path.join(log_root, "elmoCut")
        os.makedirs(log_dir, exist_ok=True)
        with open(os.path.join(log_dir, "startup.log"), "a", encoding="utf-8") as log_file:
            log_file.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except Exception:
        # Diagnostics must never prevent the application from launching.
        pass


def startup_exception_hook(exc_type, exc_value, exc_traceback):
    startup_log(
        "UNHANDLED EXCEPTION:\n"
        + "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    )
    sys.__excepthook__(exc_type, exc_value, exc_traceback)


sys.excepthook = startup_exception_hook
startup_log("=== process started ===")
startup_log(f"Frozen executable: {getattr(sys, 'frozen', False)}")

startup_log("Importing PyQt6 widgets")
from sys import argv, exit
from PyQt6.QtWidgets import QApplication, QStyleFactory, QMessageBox
startup_log("Importing PyQt6 core and network")
from PyQt6.QtCore import QTimer
from PyQt6.QtNetwork import QTcpServer, QHostAddress

startup_log("Importing tools utilities")
from tools.utils import goto
from tools.utils_gui import npcap_exists, duplicate_elmocut, repair_settings, migrate_settings_file
from tools.qtools import msg_box, Buttons, MsgIcon

startup_log("Importing GUI module")
from gui.main import ElmoCut

startup_log("Importing app assets and constants")
from assets import app_icon
from constants import *

os.environ["QT_QPA_PLATFORM"] = "windows:darkmode=0"
startup_log("Module imports completed")

IPC_HOST = "127.0.0.1"
IPC_PORT = 47653


def send_command_to_existing_instance(command):
    """Forward a local CLI command to an existing GUI before requesting elevation."""
    try:
        with socket.create_connection((IPC_HOST, IPC_PORT), timeout=0.5) as client:
            client.settimeout(1.5)
            client.sendall((command + "\n").encode("ascii"))
            return client.recv(32).strip() == b"OK"
    except OSError:
        return False


def send_ping_to_existing_instance():
    """Forward --ping to an existing instance before requesting elevation."""
    return send_command_to_existing_instance("PING")


def is_admin():
    """Return whether this process has an elevated Windows token."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def relaunch_as_admin():
    """Request elevation only when starting the main application."""
    if getattr(sys, "frozen", False):
        parameters = argv[1:]
    else:
        parameters = [os.path.abspath(__file__), *argv[1:]]

    show_command = 0 if ("--ping" in argv or "--background" in argv) else 1
    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        subprocess.list2cmdline(parameters),
        os.path.dirname(os.path.abspath(sys.executable)),
        show_command
    )
    return int(result) > 32


if __name__ == "__main__":
    startup_log("Entered main entry point")
    ping_scan = "--ping" in argv
    background_mode = ping_scan or "--background" in argv
    startup_log(f"CLI ping requested: {ping_scan}")
    startup_log(f"Background mode requested: {background_mode}")

    # Forward to an existing app before asking Windows for elevation.
    if ping_scan:
        startup_log("Checking for an existing GUI instance")
        if send_ping_to_existing_instance():
            startup_log("Existing GUI acknowledged --ping; exiting launcher")
            exit(0)
        startup_log("No existing GUI acknowledged --ping")
    elif "--background" in argv:
        startup_log("Checking for an existing GUI instance for background mode")
        if send_command_to_existing_instance("BACKGROUND"):
            startup_log("Existing GUI switched to background; exiting launcher")
            exit(0)
        startup_log("No existing GUI acknowledged background mode")

    # Request elevation only if a new main application instance is needed.
    startup_log("Checking administrator token")
    admin_status = is_admin()
    startup_log(f"Administrator token present: {admin_status}")
    if not admin_status:
        startup_log("Requesting elevation for new GUI instance")
        elevated = relaunch_as_admin()
        startup_log(f"Elevation request accepted: {elevated}")
        if not elevated:
            exit(1)
        exit(0)

    if ping_scan:
        argv.remove("--ping")
    if "--background" in argv:
        argv.remove("--background")

    startup_log("Creating QApplication")
    app = QApplication(argv)
    startup_log("QApplication created")
    app.setStyle(QStyleFactory.create("Fusion"))
    startup_log("Fusion style applied")
    icon = ElmoCut.processIcon(app_icon)
    is_restarting = "--restarting" in argv

    # Check if Npcap is installed
    startup_log("Checking Npcap installation")
    npcap_installed = npcap_exists()
    startup_log(f"Npcap installed: {npcap_installed}")
    if not npcap_installed:
        startup_log("Showing Npcap-missing dialog")
        if msg_box("elmoCut", "Npcap is not installed\n\nClick OK to download",
                    MsgIcon.CRITICAL, icon, Buttons.OK | Buttons.CANCEL) == Buttons.OK:
            goto(NPCAP_URL)
        startup_log("Npcap-missing dialog closed")

    # Check if another elmoCut process is running
    elif not is_restarting:
        startup_log("Checking for duplicate elmoCut process")
        already_running = duplicate_elmocut()
        startup_log(f"Duplicate process found: {already_running}")
        if already_running:
            msg_box("elmoCut", "elmoCut is already running!", MsgIcon.WARN, icon)
            startup_log("Duplicate-process dialog closed")
        else:
            already_running = False
    else:
        already_running = False

    # Run the GUI
    if npcap_installed and not already_running:
        startup_log("Migrating settings")
        migrate_settings_file()
        startup_log("Settings migration completed")
        startup_log("Repairing settings")
        repair_settings()
        startup_log("Settings repair completed")
        startup_log("Constructing ElmoCut window")
        GUI = ElmoCut()
        GUI.background_mode = background_mode
        startup_log("ElmoCut window constructed")

        # Background command invocations keep the tray icon active but leave
        # the main window hidden. Users can open it later from the tray menu.
        if background_mode:
            startup_log("Background mode: leaving main window hidden")
            GUI.hide()
        else:
            startup_log("Showing main window")
            GUI.showNormal()
            GUI.show()
            GUI.raise_()
            GUI.activateWindow()
            app.processEvents()
            startup_log(f"Main window show calls completed; visible={GUI.isVisible()}")

        startup_state = {"ready": False}

        # Listen on loopback so an unelevated --ping invocation can contact
        # this GUI without triggering another UAC prompt.
        ipc_server = QTcpServer()
        if not ipc_server.listen(QHostAddress(IPC_HOST), IPC_PORT):
            startup_log(f"IPC listener failed: {ipc_server.errorString()}")
            print(f"[elmoCut] Could not start local command listener: {ipc_server.errorString()}")
        else:
            startup_log(f"IPC listener listening on {IPC_HOST}:{IPC_PORT}")

        def run_ping_scan_when_idle():
            # Do not start another scan until startup and any current scan finish.
            if not startup_state["ready"] or GUI.scan_thread.isRunning():
                QTimer.singleShot(150, run_ping_scan_when_idle)
                return

            # Keep the current visible/hidden state when the CLI pings an
            # already running instance; do not steal focus.
            GUI.scanHard(silent=True)

        def accept_cli_connections():
            while ipc_server.hasPendingConnections():
                connection = ipc_server.nextPendingConnection()
                connection.disconnected.connect(connection.deleteLater)
                buffer = bytearray()
                state = {"handled": False}

                def handle_cli_request(connection=connection, buffer=buffer, state=state):
                    if state["handled"]:
                        return

                    buffer.extend(bytes(connection.readAll()))
                    if b"\n" not in buffer:
                        return

                    command = bytes(buffer).split(b"\n", 1)[0].strip()
                    state["handled"] = True
                    if command == b"PING":
                        connection.write(b"OK\n")
                        QTimer.singleShot(0, run_ping_scan_when_idle)
                    elif command == b"BACKGROUND":
                        GUI.background_mode = True
                        GUI.silent_scan = True
                        GUI.hide_all()
                        connection.write(b"OK\n")
                    else:
                        connection.write(b"ERROR\n")

                    connection.flush()
                    connection.disconnectFromHost()

                connection.readyRead.connect(handle_cli_request)
                if connection.bytesAvailable():
                    handle_cli_request()

        ipc_server.newConnection.connect(accept_cli_connections)

        def initialize_gui():
            try:
                startup_log("Deferred GUI initialization started")
                startup_log("Calling GUI.resizeEvent")
                GUI.resizeEvent()
                startup_log("Initializing scanner")
                GUI.scanner.init()
                startup_log("Scanner initialized")
                GUI.killer.iface = GUI.scanner.iface
                startup_log("Synchronizing IP forwarding state")
                GUI.sync_ip_forwarding_state()
                startup_log("Flushing ARP cache")
                GUI.scanner.flush_arp()
                startup_log("ARP cache flush completed")

                if ping_scan:
                    startup_log("Starting requested hard/ping scan")
                    GUI.scanHard(silent=background_mode)
                else:
                    startup_log("Starting initial easy scan")
                    GUI.scanEasy(silent=background_mode)

                startup_log("Version update checks are disabled")
                startup_state["ready"] = True
                startup_log("GUI initialization marked ready")

                # Reassert visibility only for normal interactive startup.
                if not background_mode:
                    GUI.showNormal()
                    GUI.raise_()
                    GUI.activateWindow()
            except Exception:
                details = traceback.format_exc()
                startup_log("STARTUP EXCEPTION:\n" + details)
                print(details)
                if not background_mode:
                    QMessageBox.critical(
                        GUI,
                        "elmoCut startup error",
                        "elmoCut encountered an error during startup.\n\n"
                        "Diagnostic log: %LOCALAPPDATA%\\elmoCut\\startup.log"
                    )

        # Start the Qt event loop first so the window can paint while
        # network/system startup runs.
        startup_log("Scheduling deferred GUI initialization")
        QTimer.singleShot(0, initialize_gui)
        startup_log("Entering Qt event loop")
        result = app.exec()
        startup_log(f"Qt event loop exited with code {result}")
        exit(result)
