from p2ptrust.testing.experiments.sampler import Attack
from p2ptrust.testing.experiments.utils import NetworkUpdate


class DeviceBenign:
    def __init__(self, ip_address="0.0.0.0", name="", port=0):
        self.ip_address = ip_address
        self.name = name
        self.port = port

    def on_round_start(self, round_no: int):
        if round_no == 0:
            return NetworkUpdate.JoinWithSameIp, None
        return None, None

    def choose_round_behavior(self, round_no: int, peer_ips: list):
        attack_plan = dict.fromkeys(peer_ips, Attack.Benign)
        return attack_plan

    def on_round_end(self, round_no: int):
        pass
