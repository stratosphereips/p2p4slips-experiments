from p2ptrust.testing.experiments.custom_devices.device import Device
from p2ptrust.testing.experiments.sampler import Attack


class DeviceMalicious(Device):
    def __init__(self, ip_address="0.0.0.0", name="", port=0):
        super().__init__(ip_address, name, port)
        self.is_good = False

    def choose_round_behavior(self, round_no: int, peer_ips: list):
        attack_plan = dict.fromkeys(peer_ips, Attack.GeneralAttack)
        return attack_plan
