from p2ptrust.testing.experiments.custom_devices.device import Device


class IPDatabase:
    def __init__(self, peers):
        self.ips = {}
        self.names = {}
        self.ports = {}
        self.peers = peers

        for peer in peers:
            self.ips[peer.ip_address] = peer
            self.names[peer.name] = peer
            try:
                self.ports[peer.port] = peer
            except AttributeError:
                print("Couldn't find port of " + peer.name)

    def update_ip(self, peer: Device, ip_address):
        if ip_address in self.ips.keys() and peer.ip_address != ip_address:
            # cannot claim ip, it is taken by another peer
            raise ValueError()
        old_ip = peer.ip_address
        self.ips[old_ip] = None
        self.ips[ip_address] = peer
        peer.ip_address = ip_address

    def deactivate_peer(self, peer: Device):
        peer.active = False
        self.ips[peer.ip_address] = None

    def activate_peer_on_ip(self, peer: Device, ip_address: str):
        self.update_ip(peer, ip_address)
        peer.active = True
