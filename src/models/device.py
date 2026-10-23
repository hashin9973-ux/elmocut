class Device:
    def __init__(self, **kwargs):
        self.ip = kwargs['ip']
        self.mac = kwargs['mac']
        self.vendor = kwargs['vendor']
        self.type = kwargs['dtype']
        self.hostname = kwargs.get('hostname', '')
        self.name = kwargs['name']
        self.admin = kwargs['admin']
        # Online status is refreshed by every scan. Older records remain
        # selectable but are visually marked as unavailable.
        self.online = kwargs.get('online', True)

    def __str__(self):
        return f"Device(name={self.name}, ip={self.ip}, mac={self.mac})"

    def __repr__(self):
        return self.__str__()

    def to_dict(self):
        return self.__dict__.copy()