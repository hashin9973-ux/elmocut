from sys import argv, exit
from PyQt6.QtWidgets import QApplication, QStyleFactory
from PyQt6.QtCore import QTimer
from PyQt6.QtNetwork import QLocalServer, QLocalSocket

from tools.utils import goto
from tools.utils_gui import npcap_exists, duplicate_elmocut, repair_settings, migrate_settings_file
from tools.qtools import msg_box, Buttons, MsgIcon

from gui.main import ElmoCut

from assets import app_icon
from constants import *

import os

os.environ["QT_QPA_PLATFORM"] = "windows:darkmode=0"

IPC_SERVER_NAME = 'elmoCutPingScan'


def send_ping_to_existing_instance():
    """Forward --ping to an already running ElmoCut instance."""
    client = QLocalSocket()
    client.connectToServer(IPC_SERVER_NAME)

    if not client.waitForConnected(500):
        client.abort()
        return False

    client.write(b'PING\n')
    client.flush()

    if not client.waitForBytesWritten(1000) or not client.waitForReadyRead(1500):
        client.abort()
        return False

    accepted = bytes(client.readAll()).strip() == b'OK'
    client.disconnectFromServer()
    return accepted


if __name__ == "__main__":
    ping_scan = '--ping' in argv
    if ping_scan:
        argv.remove('--ping')

    app = QApplication(argv)
    app.setStyle(QStyleFactory.create('Fusion'))

    # If another instance is already running, forward the ping request to it
    # instead of opening another GUI.
    if ping_scan and send_ping_to_existing_instance():
        exit(0)

    icon = ElmoCut.processIcon(app_icon)
    is_restarting = '--restarting' in argv

    # Check if Npcap is installed
    if not npcap_exists():
        if msg_box('elmoCut', 'Npcap is not installed\n\nClick OK to download',
                    MsgIcon.CRITICAL, icon, Buttons.OK | Buttons.CANCEL) == Buttons.OK:
            goto(NPCAP_URL)
    
    # Check if another elmoCut process is running
    elif not is_restarting and duplicate_elmocut():
        msg_box('elmoCut', 'elmoCut is already running!', MsgIcon.WARN, icon)
    
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

        # Listen for --ping requests from subsequent command-line invocations.
        ipc_server = QLocalServer()
        if not ipc_server.listen(IPC_SERVER_NAME):
            QLocalServer.removeServer(IPC_SERVER_NAME)
            ipc_server.listen(IPC_SERVER_NAME)

        def run_ping_scan_when_idle():
            # Wait for the initial scan to finish before starting another scan.
            if GUI.scan_thread.isRunning():
                QTimer.singleShot(150, run_ping_scan_when_idle)
                return
            GUI.scanHard()

        def accept_cli_connections():
            while ipc_server.hasPendingConnections():
                connection = ipc_server.nextPendingConnection()
                connection.disconnected.connect(connection.deleteLater)
                state = {'handled': False}

                def handle_cli_request(connection=connection, state=state):
                    if state['handled'] or not connection.bytesAvailable():
                        return

                    command = bytes(connection.readAll()).strip()
                    if command == b'PING':
                        state['handled'] = True
                        connection.write(b'OK\n')
                        connection.flush()
                        connection.disconnectFromServer()
                        QTimer.singleShot(0, run_ping_scan_when_idle)
                    else:
                        state['handled'] = True
                        connection.write(b'ERROR\n')
                        connection.flush()
                        connection.disconnectFromServer()

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
        #GUI.scanner.print_report()
        exit(app.exec())
