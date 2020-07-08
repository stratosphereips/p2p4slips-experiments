from p2ptrust.testing.experiments.custom_devices.device import Device


class IPDatabase:
    def __init__(self, devices):
        self.ips = {}
        self.names = {}
        self.ports = {}
        self.devices = devices

        for device in self.devices:
            self.ips[device.ip_address] = device
            self.names[device.name] = device
            if device.is_peer:
                self.ports[device.port] = device

    def update_ip(self, device: Device, ip_address):
        if ip_address in self.ips.keys() and device.ip_address != ip_address:
            # cannot claim ip, it is taken by another peer
            raise ValueError()
        old_ip = device.ip_address
        self.ips[old_ip] = None
        self.ips[ip_address] = device
        device.ip_address = ip_address

    def deactivate_device(self, device: Device):
        device.active = False
        self.ips[device.ip_address] = None

    def activate_device_on_ip(self, device: Device, ip_address: str):
        self.update_ip(device, ip_address)
        device.active = True

    def get_peer_ip_list(self):
        peer_ip_list = [ip for ip, device in self.ips.items() if device.is_peer]
        return peer_ip_list
