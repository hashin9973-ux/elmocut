from tools.utils_gui import get_settings, set_settings

class Nicknames:
    @staticmethod
    def _normalize_mac(mac):
        return str(mac).strip().upper().replace('-', ':')

    @staticmethod
    def _normalize_database(stored):
        normalized = {}
        for mac, name in (stored or {}).items():
            key = Nicknames._normalize_mac(mac)
            old_name = normalized.get(key, '-')
            # When legacy key formats collide, preserve the user-assigned name
            # instead of letting a default/empty entry replace it.
            if key not in normalized or (
                old_name in ('', '-') and name not in ('', '-')
            ):
                normalized[key] = name
        return normalized

    def __init__(self):
        # A case or dash/colon formatting difference must not make a saved
        # nickname disappear when a device is discovered again.
        self.__db = self._normalize_database(get_settings('nicknames'))

    def get_name(self, mac):
        return self.__db.get(self._normalize_mac(mac), '-')

    def set_name(self, mac, name):
        self.__db = self._normalize_database(get_settings('nicknames'))
        self.__db[self._normalize_mac(mac)] = name
        set_settings('nicknames', self.__db)

    def reset_name(self, mac):
        self.__db = self._normalize_database(get_settings('nicknames'))
        self.__db.pop(self._normalize_mac(mac), None)
        set_settings('nicknames', self.__db)

    @property
    def nicknames_database(self):
        return self.__db