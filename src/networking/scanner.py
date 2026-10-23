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
        Flush ARP cache
        """
        arp_cmd = terminal(CMD_ARP_CACHE_FLUSH)

        # terminal() returns None on CalledProcessError — treat that the
        # same as the known "incorrect parameter" case and fall back.
        needs_fallback = arp_cmd is None or 'The parameter is incorrect' in arp_cmd

        if needs_fallback:
            result = terminal(CMD_ARP_CACHE_FLUSH_NEW)
            if result is None:
                print('[Scanner] ARP cache flush failed via both arp.exe and netsh.')

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
        """Try Windows NetBIOS name discovery, then reverse DNS."""
        try:
            result = subprocess.run(
                ["nbtstat", "-A", ip],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=1.5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            for line in result.stdout.splitlines():
                match = re.match(
                    r"^\\s*([^\\s<]+)\\s+<00>\\s+UNIQUE\\b",
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

        try:
            previous_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(1.0)
            try:
                return socket.gethostbyaddr(ip)[0].rstrip(".").split(".")[0]
            finally:
                socket.setdefaulttimeout(previous_timeout)
        except (OSError, socket.herror, socket.gaierror):
            return ""

    def advanced_scan(self):
        """
        Discover devices across the local /24 using both ARP and ICMP, then
        enrich each result with a Windows NetBIOS name or reverse-DNS hostname.
        """
        self.init()
        try:
            network = ipaddress.ip_network(f"{self.my_ip}/24", strict=False)
        except ValueError:
            print(f"[Scanner] Cannot determine local IPv4 network from {self.my_ip!r}")
            self.devices_appender([])
            return

        target_ips = [
            str(address) for address in network.hosts()
            if str(address) != self.my_ip
        ]
        self.qt_progress_signal(0)

        # ARP finds local devices even when they ignore ICMP echo requests.
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
                if ip and mac:
                    discovered[ip] = mac
        except Exception as exc:
            print(f"[Scanner] Advanced ARP discovery failed: {exc}")

        # Also perform a bounded-concurrency ping sweep. Successful replies can
        # populate the Windows ARP cache and supplement the direct ARP results.
        def ping_target(ip):
            try:
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", "500", ip],
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
                except Exception:
                    pass
                self.qt_progress_signal(completed)

        # Merge IP-to-MAC mappings learned by Windows while the ping sweep ran.
        cache_output = terminal(CMD_ARP_CACHE(self.my_ip))
        if cache_output:
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
                if re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
                    discovered.setdefault(ip, mac)

        # Resolve names only for devices with a known MAC, avoiding a lengthy
        # name lookup for every address in the subnet.
        hostnames = {}
        with ThreadPoolExecutor(max_workers=16) as executor:
            futures = {
                executor.submit(self._resolve_device_name, ip): ip
                for ip in discovered
                if ip not in (self.my_ip, self.router_ip)
            }
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    hostnames[ip] = future.result() or ""
                except Exception:
                    hostnames[ip] = ""

        scan_result = [(ip, mac) for ip, mac in discovered.items()]
        print(
            f"[Scanner] Advanced scan found {len(scan_result)} local devices "
            f"({len(ping_alive)} ICMP responders) on {network}"
        )
        self.devices_appender(scan_result, hostnames)

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