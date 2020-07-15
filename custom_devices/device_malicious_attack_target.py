from p2ptrust.testing.experiments.custom_devices.device import Device
from p2ptrust.testing.experiments.sampler import Attack


class DeviceMaliciousAttackTarget(Device):
    def __init__(self, ip_address="0.0.0.0", name="", is_good=False, victim_list=None):
        self.is_good = is_good
        self.victim_list_in_rounds = victim_list
        super().__init__(ip_address, name, self.is_good)

    def choose_round_behavior(self, round_no: int, peer_ips: list):
        victim_list = self.victim_list_in_rounds[round_no]
        attack_plan_victims = dict.fromkeys(victim_list, Attack.GeneralAttack)

        friend_list = list(set(peer_ips) - set(victim_list))
        attack_plan_friends = dict.fromkeys(friend_list, Attack.Benign)

        attack_plan = {**attack_plan_friends, **attack_plan_victims}
        return attack_plan
