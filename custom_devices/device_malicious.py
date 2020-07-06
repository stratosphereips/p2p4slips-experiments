from p2ptrust.testing.experiments.sampler import Attack
from p2ptrust.testing.experiments.utils import NetworkUpdate


class DeviceMalicious:
    def __init__(self, ip_address="0.0.0.0", name="", port=0):
        self.ip_address = ip_address
        self.name = name
        self.port = port
        self.is_good = False

    def on_round_start(self, round_no: int):
        if round_no == 0:
            return NetworkUpdate.JoinWithSameIp, None
        return None, None

    def choose_round_behavior(self, round_no: int, peer_ips: list):
        attack_plan = dict.fromkeys(peer_ips, Attack.GeneralAttack)
        return attack_plan

    def on_round_end(self, round_no: int):
        pass
