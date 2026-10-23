from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import arping, ARP, Ether, srp
from time import sleep
import errno
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
        # Count only credible advanced scans that miss a known device.
        self.missed_advanced_scans = {}
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

    def devices_appender(self, scan_result, hostnames=None, mark_missing_offline=False, port_results=None):
        """
        Merge discovered devices without treating a weak scan as proof that
        previously known devices went offline.

        Basic scans never mark absent devices offline because their discovery
        methods have different coverage. Advanced scans must repeatedly produce
        a credible result before an absent device is shown as unavailable.
        """
        nicknames = Nicknames()
        hostnames = hostnames or {}
        has_port_results = port_results is not None
        port_results = port_results or {}
        previous_devices = {
            device.mac: device for device in self.devices
            if not device.admin and device.mac
        }
        previous_online_macs = {
            mac for mac, device in previous_devices.items()
            if getattr(device, "online", True)
        }

        # Validate input before using it to decide whether a scan was complete.
        # Empty, malformed, or MAC-less results are not evidence of absence.
        clean_results = []
        for entry in scan_result or []:
            if not isinstance(entry, (tuple, list)) or len(entry) < 2:
                continue
            ip = str(entry[0]).strip("()")
            try:
                parsed_ip = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if parsed_ip.version != 4 or ip in (self.router_ip, self.my_ip):
                continue

            mac = good_mac(str(entry[1]))
            if (
                not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac)
                or mac == GLOBAL_MAC
            ):
                continue
            clean_results.append((ip, mac, entry))

        clean_results.sort(key=lambda item: int(item[0].rsplit(".", 1)[-1]))
        discovered_macs = {mac for _, mac, _ in clean_results}
        previously_known_hits = len(previous_online_macs & discovered_macs)
        required_known_hits = max(1, (len(previous_online_macs) + 1) // 2)
        credible_advanced_result = (
            mark_missing_offline
            and previously_known_hits >= required_known_hits
        )

        self.devices = []
        seen_macs = set()
        active_macs = set()

        for ip, mac, entry in clean_results:
            if mac in seen_macs:
                continue

            seen_macs.add(mac)
            active_macs.add(mac)
            previous = previous_devices.get(mac)
            self.old_ips[mac] = ip

            # Persisted user nicknames always win. If a legacy/corrupt MAC key
            # prevented lookup, retain the in-memory custom nickname as fallback.
            nickname = nicknames.get_name(mac)
            if nickname in ("", None, "-") and previous is not None:
                previous_name = getattr(previous, "name", "-")
                if previous_name not in ("", None, "-"):
                    nickname = previous_name
            if nickname in ("", None):
                nickname = "-"

            hostname = hostnames.get(ip, "")
            if not hostname and len(entry) > 2:
                hostname = str(entry[2] or "")
            if not hostname and previous is not None:
                hostname = previous.hostname

            self.missed_advanced_scans[mac] = 0
            self.devices.append(
                Device(
                    ip=ip,
                    mac=mac,
                    vendor=get_vendor(mac),
                    dtype=DeviceType.USER,
                    hostname=hostname,
                    open_ports=(
                        sorted(set(port_results.get(ip, [])))
                        if has_port_results
                        else list(getattr(previous, 'open_ports', [])) if previous is not None else []
                    ),
                    name=nickname,
                    admin=False,
                    online=True
                )
            )

        # A device must be absent from three credible advanced sweeps before
        # it is greyed out. Zero-result and low-coverage scans do not count.
        for mac, device in previous_devices.items():
            if mac not in active_macs:
                if credible_advanced_result:
                    misses = self.missed_advanced_scans.get(mac, 0) + 1
                    self.missed_advanced_scans[mac] = misses
                    if misses >= 3:
                        device.online = False
                self.devices.append(device)

        # Retain watched devices that are not in Scanner.devices yet.
        for mac in set(self.parent.watched_devices.keys()) - active_macs:
            if mac in previous_devices:
                continue
            window = self.parent.device_windows.get(mac)
            if window and window.device:
                if credible_advanced_result:
                    misses = self.missed_advanced_scans.get(mac, 0) + 1
                    self.missed_advanced_scans[mac] = misses
                    if misses >= 3:
                        window.device.online = False
                self.devices.append(window.device)

        # Keep mappings for active and retained devices so IP changes remain
        # associated with the same MAC address on subsequent scans.
        self.old_ips = {d.mac: d.ip for d in self.devices if d.mac}

        self.add_me()
        self.add_router()

        print(
            f"Scanner found {len(self.devices)} devices "
            f"({len(active_macs)} discovered user MACs; "
            f"credible advanced result={credible_advanced_result}): {self.devices}"
        )

        # Clear the ARP cache only after some devices were captured.
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
        Discover local devices using ARP, repeated ICMP, common TCP service
        probes, Windows neighbour-cache data, and bounded hostname lookups.
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

        # If the direct srp sweep is empty or misses most previously online
        # devices, retry with the same Scapy arping path used by Easy Scan.
        # The two paths are similar but can behave differently across Windows
        # adapters/Npcap versions, so combine their answers instead of trusting
        # a single intermittently weak sweep.
        previous_online_macs = {
            device.mac for device in self.devices
            if not device.admin and getattr(device, "online", True) and device.mac
        }
        known_found = len(previous_online_macs.intersection(discovered.values()))
        should_retry_arp = not discovered or (
            bool(previous_online_macs)
            and known_found < max(1, (len(previous_online_macs) + 1) // 2)
        )
        if should_retry_arp:
            try:
                fallback_result = arping(
                    f"{self.router_ip}/24",
                    iface=self.iface.name,
                    verbose=0,
                    timeout=2
                )
                for _, received in fallback_result[0]:
                    ip, mac = received.psrc, good_mac(received.src)
                    if ip and mac and mac != GLOBAL_MAC:
                        discovered.setdefault(ip, mac)
            except Exception as exc:
                print(f"[Scanner] Fallback arping discovery failed: {exc}")

        # Repeat ICMP and probe TCP services to find hosts that block echo
        # requests but expose a common service. This is an independent
        # implementation using documented discovery methods, not copied code
        # from Advanced IP Scanner.
        def ping_target(ip):
            try:
                result = subprocess.run(
                    ["ping", "-n", "2", "-w", "450", ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2.0,
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
                self.qt_progress_signal(min(140, int(140 * completed / len(target_ips))))

        # Probe common Windows, server, printer, camera and web services.
        # A successful connection OR a TCP refusal is evidence of a live host
        # even when ICMP is blocked (a refusal means the host sent a TCP RST).
        tcp_ports = (21, 22, 23, 53, 80, 135, 139, 443, 445, 554, 3389, 5900, 8080, 9100)

        def tcp_port_open(ip, port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                    connection.settimeout(0.22)
                    result = connection.connect_ex((ip, port))
                    if result == 0:
                        return "open"
                    if result in (errno.ECONNREFUSED, 10061):
                        return "responsive"
                    return ""
            except OSError:
                return ""

        tcp_alive = set()
        open_ports_by_ip = {}
        port_targets = [(ip, port) for ip in target_ips for port in tcp_ports]
        with ThreadPoolExecutor(max_workers=128) as executor:
            futures = {
                executor.submit(tcp_port_open, ip, port): (ip, port)
                for ip, port in port_targets
            }
            for completed, future in enumerate(as_completed(futures), start=1):
                ip, port = futures[future]
                try:
                    probe_status = future.result()
                    if probe_status:
                        tcp_alive.add(ip)
                    if probe_status == "open":
                        open_ports_by_ip.setdefault(ip, []).append(port)
                except Exception as exc:
                    print(f"[Scanner] TCP probe for {ip}:{port} failed: {exc}")
                if completed % len(tcp_ports) == 0 or completed == len(port_targets):
                    self.qt_progress_signal(
                        140 + int(70 * completed / len(port_targets))
                    )

        responsive_ips = ping_alive | tcp_alive | set(discovered.keys())

        # Use cached entries only for hosts that showed positive evidence in
        # this scan. Old/stale ARP records must not keep offline hosts active.
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
                ip in responsive_ips
                and re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac)
                and mac != GLOBAL_MAC
            ):
                discovered.setdefault(ip, mac)

        # ICMP/TCP responders missing a cached MAC get a targeted ARP attempt.
        missing_mac_ips = sorted(
            responsive_ips - set(discovered.keys()),
            key=lambda value: int(value.rsplit(".", 1)[-1])
        )
        if missing_mac_ips:
            try:
                arp_packets = [
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
                    for ip in missing_mac_ips
                ]
                answered, _ = srp(
                    arp_packets,
                    iface=self.iface.name,
                    timeout=1.2,
                    retry=0,
                    verbose=0
                )
                for _, received in answered:
                    ip, mac = received.psrc, good_mac(received.hwsrc)
                    if ip and mac and mac != GLOBAL_MAC:
                        discovered[ip] = mac
            except Exception as exc:
                print(f"[Scanner] Targeted ARP resolution failed: {exc}")

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
                        210 + int(42 * completed / len(name_ips))
                    )
        else:
            self.qt_progress_signal(252)

        scan_result = [(ip, mac) for ip, mac in discovered.items()]
        print(
            f"[Scanner] Advanced scan found {len(scan_result)} local devices "
            f"({len(ping_alive)} ICMP responders, "
            f"{len(tcp_alive)} TCP responders) on {network}"
        )

        # Commit results before marking the scan complete.
        self.devices_appender(
            scan_result,
            hostnames,
            mark_missing_offline=True,
            port_results=open_ports_by_ip
        )
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