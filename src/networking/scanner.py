from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import arping, ARP, Ether, srp
from time import sleep
import ipaddress
import re
import socket
import subprocess
from networking.nicknames import Nicknames
from tools.utils import *
from constants import *
from models.device import Device
from enums import DeviceType
from scapy.all import sniff, DHCP, BOOTP, Ether
from tools.utils import threaded, good_mac

class Scanner():
    def __init__(self, _parent):
        self.parent = _parent
        self.iface = get_default_iface()
        self.device_count = 25
        self.max_threads = 8
        self.__ping_done = 0
        self.devices = []
        self.old_ips = {}
        self.router = {}
        self.ips = []
        self.me = {}
        self.perfix = None
        self.qt_progress_signal = int
        self.qt_log_signal = print
    
    def generate_ips(self):
        self.ips = [f'{self.perfix}.{i}' for i in range(1, self.device_count)]

    def init(self):
        """
        Intializing Scanner
        """
        self.iface = get_iface_by_name(self.iface.name)

        # Keep the last result set until devices_appender compares it with
        # the latest scan. Devices that did not answer become offline records.
        self.router_ip = get_gateway_ip(self.iface.name)
        self.router_mac = get_gateway_mac(self.iface.ip, self.router_ip)

        self.my_ip = get_my_ip(self.iface.name)
        self.my_mac = good_mac(self.iface.mac)
        
        self.perfix = self.my_ip.rsplit(".", 1)[0]
        self.generate_ips()
    
    def flush_arp(self):
        """
        Flush ARP cache with timeouts so a Windows command cannot hold a scan
        open indefinitely after its results have already been collected.
        """
        no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            arp_result = subprocess.run(
                CMD_ARP_CACHE_FLUSH,
                shell=True,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=2.0,
                creationflags=no_window
            )
            arp_output = (arp_result.stdout or "") + (arp_result.stderr or "")
            needs_fallback = (
                arp_result.returncode != 0
                or "The parameter is incorrect" in arp_output
            )
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"[Scanner] arp.exe cache flush timed out or failed: {exc}")
            needs_fallback = True

        if needs_fallback:
            try:
                fallback = subprocess.run(
                    CMD_ARP_CACHE_FLUSH_NEW,
                    shell=True,
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=2.0,
                    creationflags=no_window
                )
                if fallback.returncode != 0:
                    print(
                        "[Scanner] ARP cache flush failed via arp.exe and netsh: "
                        + ((fallback.stderr or fallback.stdout or "").strip())
                    )
            except (OSError, subprocess.SubprocessError) as exc:
                print(f"[Scanner] netsh ARP cache flush timed out or failed: {exc}")

    def add_me(self):
        """
        Get My info and append to self.devices
        """
        self.me = Device(
            ip = self.my_ip,
            mac = self.my_mac,
            vendor = get_vendor(self.my_mac),
            dtype = DeviceType.OWNER,
            name = '',
            admin = True
        )
        
        self.devices.insert(0, self.me)

    def add_router(self):
        """
        Get Gateway info and append to self.devices
        """
        self.router = Device(
            ip = self.router_ip,
            mac = self.router_mac,
            vendor = get_vendor(self.router_mac),
            dtype = DeviceType.ROUTER,
            name = '',
            admin = True
        )

        self.devices.insert(0, self.router)

    def devices_appender(self, scan_result, hostnames=None):
        """
        Refresh active devices while retaining previously known devices that
        no longer answer. Retained records stay selectable and are marked offline.
        """
        nicknames = Nicknames()
        hostnames = hostnames or {}
        previous_devices = {
            device.mac: device for device in self.devices
            if not device.admin and device.mac
        }

        self.devices = []
        seen_macs = set()
        active_macs = set()

        # Sort by the last IPv4 octet for a stable table.
        scan_result = sorted(
            scan_result,
            key=lambda item: int(str(item[0]).strip("()").split(".")[-1])
        )

        for entry in scan_result:
            if len(entry) < 2:
                continue
            ip, mac = str(entry[0]).strip("()"), good_mac(str(entry[1]))
            if ip in [self.router_ip, self.my_ip] or mac in seen_macs:
                continue

            seen_macs.add(mac)
            active_macs.add(mac)
            previous = previous_devices.get(mac)
            self.old_ips[mac] = ip

            nickname = nicknames.get_name(mac)
            if nickname == "-" and previous is not None:
                nickname = previous.name

            hostname = hostnames.get(ip, "")
            if not hostname and len(entry) > 2:
                hostname = str(entry[2] or "")
            if not hostname and previous is not None:
                hostname = previous.hostname

            self.devices.append(
                Device(
                    ip=ip,
                    mac=mac,
                    vendor=get_vendor(mac),
                    dtype=DeviceType.USER,
                    hostname=hostname,
                    name=nickname,
                    admin=False,
                    online=True
                )
            )

        # Retain disappeared devices with their last-known details. This does
        # not disable row selection or the existing device actions.
        for mac, device in previous_devices.items():
            if mac not in active_macs:
                device.online = False
                self.devices.append(device)

        # Also retain any watched device not yet represented in the last scan.
        for mac in set(self.parent.watched_devices.keys()) - active_macs:
            if mac in previous_devices:
                continue
            window = self.parent.device_windows.get(mac)
            if window and window.device:
                window.device.online = False
                self.devices.append(window.device)

        # Keep the mapping for active and retained devices so an IP change for a
        # known MAC is handled on the next scan.
        self.old_ips = {d.mac: d.ip for d in self.devices if d.mac}

        self.add_me()
        self.add_router()

        print(f'Scanner found {len(self.devices)} devices: {self.devices}')

        # Clear the ARP cache after results have been captured.
        if active_macs:
            self.flush_arp()
    
    def arping_cache(self):
        """
        Showing system arp cache after pinging
        """
        # Correct scan result when working with specific interface
        scan_result = terminal(CMD_ARP_CACHE(self.my_ip))
        
        if not scan_result:
            print('ARP error has been caught!')
            self.devices_appender([])
            return

        clean_result = [line.split()[:2] for line in scan_result.split('\n') if line.split()]
        self.devices_appender(clean_result)
    
    def _resolve_device_name(self, ip):
        """Resolve a name using bounded Windows commands only."""
        try:
            result = subprocess.run(
                ["nbtstat", "-A", ip],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=1.0,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            for line in result.stdout.splitlines():
                match = re.match(
                    r"^\s*([^\s<]+)\s+<00>\s+UNIQUE\b",
                    line,
                    re.IGNORECASE
                )
                if match:
                    hostname = match.group(1).strip()
                    if hostname and hostname.upper() not in {
                        "WORKGROUP", "__MSBROWSE__"
                    }:
                        return hostname
        except (OSError, subprocess.SubprocessError):
            pass

        # Reverse lookup APIs can block inside the system resolver. Use ping
        # with -a instead so this fallback has a hard subprocess timeout too.
        try:
            result = subprocess.run(
                ["ping", "-a", "-n", "1", "-w", "300", ip],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=1.0,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            for line in result.stdout.splitlines():
                match = re.match(
                    r"^Pinging\s+(.+?)\s+\[\d{1,3}(?:\.\d{1,3}){3}\]",
                    line,
                    re.IGNORECASE
                )
                if match:
                    hostname = match.group(1).strip().rstrip(".")
                    if hostname and hostname != ip:
                        return hostname
        except (OSError, subprocess.SubprocessError):
            pass
        return ""

    def advanced_scan(self):
        """
        Discover devices across the local /24 using ARP and ICMP, then enrich
        known MAC addresses with bounded NetBIOS/reverse-name lookups.
        """
        self.init()
        try:
            network = ipaddress.ip_network(f"{self.my_ip}/24", strict=False)
        except ValueError:
            raise RuntimeError(
                f"Cannot determine local IPv4 network from {self.my_ip!r}"
            )

        target_ips = [
            str(address) for address in network.hosts()
            if str(address) != self.my_ip
        ]
        if not target_ips:
            raise RuntimeError(f"No scan targets found for {network}")

        self.qt_progress_signal(0)

        # ARP can discover hosts that ignore ICMP echo requests.
        discovered = {}
        try:
            answered, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
                iface=self.iface.name,
                timeout=1.5,
                retry=1,
                verbose=0
            )
            for _, received in answered:
                ip, mac = received.psrc, good_mac(received.hwsrc)
                if ip and mac and mac != GLOBAL_MAC:
                    discovered[ip] = mac
        except Exception as exc:
            print(f"[Scanner] Advanced ARP discovery failed: {exc}")

        # Ping the complete subnet with bounded concurrency and no visible
        # console windows. These replies also warm the Windows neighbor cache.
        def ping_target(ip):
            try:
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", "400", ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=1.5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
                return result.returncode == 0
            except (OSError, subprocess.SubprocessError):
                return False

        ping_alive = set()
        with ThreadPoolExecutor(max_workers=64) as executor:
            futures = {executor.submit(ping_target, ip): ip for ip in target_ips}
            for completed, future in enumerate(as_completed(futures), start=1):
                ip = futures[future]
                try:
                    if future.result():
                        ping_alive.add(ip)
                except Exception as exc:
                    print(f"[Scanner] Ping task for {ip} failed: {exc}")
                self.qt_progress_signal(min(200, int(200 * completed / len(target_ips))))

        # Read the Windows ARP cache directly, including static entries. Do not
        # rely on locale-sensitive "findstr dynamic" output.
        try:
            cache = subprocess.run(
                ["arp", "-a", "-N", self.my_ip],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=3.0,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            cache_output = cache.stdout if cache.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"[Scanner] Could not read Windows ARP cache: {exc}")
            cache_output = ""

        for line in cache_output.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            ip = parts[0].strip("()")
            try:
                if ipaddress.ip_address(ip) not in network:
                    continue
            except ValueError:
                continue

            mac = good_mac(parts[1])
            if (
                re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac)
                and mac != GLOBAL_MAC
            ):
                discovered.setdefault(ip, mac)

        # Resolve names only for devices whose MAC addresses we actually know.
        # Every lookup is a process with a timeout, so name discovery cannot
        # hold the scan thread indefinitely.
        name_ips = [
            ip for ip in discovered
            if ip not in (self.my_ip, self.router_ip)
        ]
        hostnames = {}
        if name_ips:
            with ThreadPoolExecutor(max_workers=32) as executor:
                futures = {
                    executor.submit(self._resolve_device_name, ip): ip
                    for ip in name_ips
                }
                for completed, future in enumerate(as_completed(futures), start=1):
                    ip = futures[future]
                    try:
                        hostnames[ip] = future.result() or ""
                    except Exception as exc:
                        print(f"[Scanner] Name lookup for {ip} failed: {exc}")
                        hostnames[ip] = ""
                    self.qt_progress_signal(
                        200 + int(52 * completed / len(name_ips))
                    )
        else:
            self.qt_progress_signal(252)

        scan_result = [(ip, mac) for ip, mac in discovered.items()]
        print(
            f"[Scanner] Advanced scan found {len(scan_result)} local devices "
            f"({len(ping_alive)} ICMP responders) on {network}"
        )

        # Commit results before marking the scan complete.
        self.devices_appender(scan_result, hostnames)
        self.qt_progress_signal(253)

    def arp_scan(self):
        """
        Scan using Scapy arping method 
        """
        self.init()

        self.generate_ips()
        scan_result = arping(
            f"{self.router_ip}/24",
            iface=self.iface.name,
            verbose=0,
            timeout=1
        )
        clean_result = [(i[1].psrc, i[1].src) for i in scan_result[0]]

        self.devices_appender(clean_result)

    def ping_scan(self):
        """
        Ping all devices at once [CPU Killing function]
           (All Threads will run at the same tine)
        """
        self.init()
        self.__ping_done = 0
        
        self.generate_ips()
        self.ping_thread_pool()
        
        while self.__ping_done < self.device_count - 1:
            # Add a sleep to overcome High CPU usage
            sleep(.01)
            self.qt_progress_signal(self.__ping_done)
        
        return True
    
    @threaded
    def ping_thread_pool(self):
        """
        Control maximum threads running at once
        """
        with ThreadPoolExecutor(self.max_threads) as executor:
            for ip in self.ips:
                executor.submit(self.ping, ip)

    def ping(self, ip):
        """
        Ping a specific ip with native command "ping -n"
        """
        terminal(CMD_PING_DEVICE(ip), decode=False)
        self.__ping_done += 1

class DhcpSniffer:
    def __init__(self, iface):
        self.iface = iface
        self.hostnames = {}  # mac -> hostname

    @threaded
    def start(self):
        sniff(
            filter="udp and (port 67 or port 68)",
            prn=self._handle_packet,
            store=0,
            iface=self.iface.name
        )

    def _handle_packet(self, pkt):
        if DHCP not in pkt or Ether not in pkt:
            return

        mac = good_mac(pkt[Ether].src)
        opts = {opt[0]: opt[1] for opt in pkt[DHCP].options if isinstance(opt, tuple)}
        hostname = opts.get('hostname')

        if hostname:
            if isinstance(hostname, bytes):
                hostname = hostname.decode(errors='ignore')
            self.hostnames[mac] = hostname