from PyQt6.QtCore import QThread, pyqtSignal
import traceback

class ScanThread(QThread):
    # Progress and lifecycle signals are emitted even when the scan fails.
    progress = pyqtSignal(int)
    scan_error = pyqtSignal(str)
    thread_finished = pyqtSignal(bool)

    def __init__(self):
        QThread.__init__(self)

        self.scanner = None
        self.scan_type = None

    def run(self):
        # 0 = arping, 1 = the existing ping scan, 2 = advanced discovery.
        try:
            if self.scan_type == 0:
                self.easy()
            elif self.scan_type == 1:
                self.hard()
            elif self.scan_type == 2:
                self.advanced()
            else:
                raise ValueError(f"Unknown scan type: {self.scan_type!r}")
        except Exception as exc:
            details = traceback.format_exc()
            print(f"[ScanThread] Scan failed: {details}")
            self.scan_error.emit(f"{type(exc).__name__}: {exc}")
            self.thread_finished.emit(False)
        else:
            self.thread_finished.emit(True)

    def easy(self):
        # Fake progress cause Scapy can't handle QThread Signals
        self.scanner.arp_scan()
    
    def hard(self):
        # self.pinging_watcher() will use progress signal
        # to update progress bar in GUI
        self.scanner.qt_progress_signal = self.progress.emit
        self.scanner.ping_scan()
        self.scanner.arping_cache()

    def advanced(self):
        # The advanced scanner reports progress for the entire IPv4 /24 sweep.
        self.scanner.qt_progress_signal = self.progress.emit
        self.scanner.advanced_scan()

class UpdateThread(QThread):
    thread_finished = pyqtSignal(bool)

    def __init__(self):
        QThread.__init__(self)
        self.prompt_if_latest = True
        self.github_version = 'None'
        self.check_failed = False
        self.url = 'https://github.com/elmoiv/elmocut/releases/latest'

    def run(self):
        self.check_failed = False
        try:
            redirect = get(self.url, timeout=5)
            self.github_version = redirect.url.split('/')[-1]
        except Exception as e:
            print('Error at Update Thread:', e)
            self.check_failed = True

        self.thread_finished.emit(True)