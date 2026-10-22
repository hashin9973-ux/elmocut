from sys import argv, exit
from PyQt6.QtWidgets import QApplication, QStyleFactory
from PyQt6.QtCore import QTimer
from PyQt6.QtNetwork import QTcpServer, QHostAddress

from tools.utils import goto
from tools.utils_gui import npcap_exists, duplicate_elmocut, repair_settings, migrate_settings_file
from tools.qtools import msg_box, Buttons, MsgIcon

from gui.main import ElmoCut

from assets import app_icon
from constants import *

import ctypes
import os
import socket
import subprocess
import sys

os.environ["QT_QPA_PLATFORM"] = "windows:darkmode=0"

IPC_HOST = "127.0.0.1"
IPC_PORT = 47653


def send_ping_to_existing_instance():
    """Forward --ping to an existing instance before requesting elevation."""
    try:
        with socket.create_connection((IPC_HOST, IPC_PORT), timeout=0.5) as client:
            client.settimeout(1.5)
            client.sendall(b"PING\n")
            return client.recv(32).strip() == b"OK"
    except OSError:
        return False


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

    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        subprocess.list2cmdline(parameters),
        None,
        1
    )
    return int(result) > 32


if __name__ == "__main__":
    ping_scan = "--ping" in argv

    # Forward to an existing app before asking Windows for elevation.
    # The short-lived command process should exit without starting a second GUI.
    if ping_scan and send_ping_to_existing_instance():
        exit(0)

    # The EXE no longer has an always-elevated manifest. Elevate here only if
    # no existing instance handled the command and the app itself must start.
    if not is_admin():
        if not relaunch_as_admin():
            exit(1)
        exit(0)

    if ping_scan:
        argv.remove("--ping")

    app = QApplication(argv)
    app.setStyle(QStyleFactory.create("Fusion"))
    icon = ElmoCut.processIcon(app_icon)
    is_restarting = "--restarting" in argv

    # Check if Npcap is installed
    if not npcap_exists():
        if msg_box("elmoCut", "Npcap is not installed\n\nClick OK to download",
                    MsgIcon.CRITICAL, icon, Buttons.OK | Buttons.CANCEL) == Buttons.OK:
            goto(NPCAP_URL)

    # Check if another elmoCut process is running
    elif not is_restarting and duplicate_elmocut():
        msg_box("elmoCut", "elmoCut is already running!", MsgIcon.WARN, icon)

    # Run the GUI
    else:
        migrate_settings_file()
        repair_settings()
        GUI = ElmoCut()
        GUI.show()
        GUI.resizeEvent()
        GUI.scanner.init()
        GUI.killer.iface = GUI.scanner.iface
        GUI.sync_ip_forwarding_state()
        GUI.scanner.flush_arp()

        # Listen on loopback so an unelevated --ping invocation can contact
        # this elevated GUI without triggering a second UAC prompt.
        ipc_server = QTcpServer()
        if not ipc_server.listen(QHostAddress(IPC_HOST), IPC_PORT):
            print(f"[elmoCut] Could not start local command listener: {ipc_server.errorString()}")

        def run_ping_scan_when_idle():
            # Wait for the current scan to finish before starting another scan.
            if GUI.scan_thread.isRunning():
                QTimer.singleShot(150, run_ping_scan_when_idle)
                return
            GUI.scanHard()

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
                    else:
                        connection.write(b"ERROR\n")
                    connection.flush()
                    connection.disconnectFromHost()

                connection.readyRead.connect(handle_cli_request)
                if connection.bytesAvailable():
                    handle_cli_request()

        ipc_server.newConnection.connect(accept_cli_connections)

        if ping_scan:
            GUI.scanHard()
        else:
            GUI.scanEasy()
        GUI.UpdateThread_Starter()
        # Bring window to top
        GUI.activateWindow()
        # GUI.scanner.print_report()
        exit(app.exec())
