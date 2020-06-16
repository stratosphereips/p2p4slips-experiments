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

    def set_custom_ip(self, peer, ip_address):
        # TODO: check if IP is empty
        self.ips[ip_address] = peer

    def set_peer_object(self, peer_name, peer):
        self.names[peer_name] = peer


    def deactivate_peer(self, peer_name):
        peer = self.peers_by_name[peer_name]
        self.peers.remove(peer)
        self.peers_by_name[peer_name] = None

    def activate_peer(self, peer, peer_name):
        self.peers_by_name[peer_name] = peer
        self.peers.append(peer)