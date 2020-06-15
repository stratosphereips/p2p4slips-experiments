from peerwithstrategy import PeerWithStrategy


class IPDatabase:
    def __init__(self):
        self.ips = {}
        self.names = {}
        self.peers = {}
        pass

    def set_custom_ip(self, peer_name, ip_address):
        self.ips[peer_name] = ip_address
        self.names[ip_address] = peer_name

    def get_ip_of_peer(self, peer_name):
        return self.ips[peer_name]

    def get_name_on_ip(self, ip_address):
        return self.names[ip_address]

    def set_peer_object(self, peer_name, peer):
        self.peers[peer_name] = peer

    def get_peer_object(self, peer_name) -> PeerWithStrategy:
        return self.peers[peer_name]
