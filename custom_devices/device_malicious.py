from p2ptrust.testing.experiments.custom_devices.device import Device
from p2ptrust.testing.experiments.sampler import Attack


class DeviceMalicious(Device):
    def __init__(self, ip_address="0.0.0.0", name="", is_good=False):
        self.is_good = is_good
        super().__init__(ip_address, name, self.is_good)

    def choose_round_behavior(self, round_no: int, peer_ips: list):
        attack_plan = dict.fromkeys(peer_ips, Attack.GeneralAttack)
        return attack_plan
