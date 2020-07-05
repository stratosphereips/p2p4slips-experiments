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

    def update_ip(self, peer, ip_address):
        if ip_address in self.ips.keys() and peer.ipaddress != ip_address:
            # cannot claim ip, it is taken by another peer
            raise ValueError()
        old_ip = peer.ipaddress
        self.ips[old_ip] = None
        self.ips[ip_address] = peer
        peer.ipaddress = ip_address

    def deactivate_peer(self, peer: PeerWithStrategy):
        peer.active = False
        self.ips[peer.ipaddress] = None

    def activate_peer_on_ip(self, peer: PeerWithStrategy, ip_address: str):
        self.update_ip(peer, ip_address)
        peer.active = True
