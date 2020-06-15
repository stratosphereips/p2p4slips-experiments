class IPDatabase:
    def __init__(self):
        self.ips = {}
        self.names = {}
        pass

    def set_custom_ip(self, peer_name, ip_address):
        self.ips[peer_name] = ip_address
        self.names[ip_address] = peer_name

    def get_ip_of_peer(self, peer_name):
        return self.ips[peer_name]

    def get_name_on_ip(self, ip_address):
        return self.names[ip_address]
