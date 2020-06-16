from peerwithstrategy import PeerWithStrategy


class IPDatabase:
    def __init__(self, peers):
        self.ips = {}
        self.names = {}
        self.ports = {}
        self.peers = peers

        for peer in peers:
            self.ips[peer.ipaddress] = peer
            self.names[peer.name] = peer
            self.ports[peer.port] = peer

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



    def deactivate_peer(self, peer_name):
        peer = self.peers_by_name[peer_name]
        self.peers.remove(peer)
        self.peers_by_name[peer_name] = None

    def activate_peer(self, peer, peer_name):
        self.peers_by_name[peer_name] = peer
        self.peers.append(peer)