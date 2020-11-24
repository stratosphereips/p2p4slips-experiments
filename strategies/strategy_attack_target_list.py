from modules.p2ptrust.testing.experiments.sampler import Attack
from modules.p2ptrust.testing.experiments.strategies.basic_strategy import Strategy
from modules.p2ptrust.testing.experiments.utils import NetworkUpdate


class StrategyAttackTargetList(Strategy):

    def __init__(self, target_ip_list, start_at_round = 0, stop_before_round = 1000000):
        super().__init__()
        self.target_ip_list = target_ip_list
        self.override_handle_update = True
        self.override_handle_data_request = True
        self.is_good = False
        self.do_p2p = False
        self.start_at_round = start_at_round
        self.stop_before_round = stop_before_round

    def on_round_start(self, round_no: int):
        if round_no == 0:
            return NetworkUpdate.JoinWithSameIp, None
        return None, None

    def choose_round_behavior(self, round_no: int, peer_ips: list):
        if round_no >= self.stop_before_round or round_no < self.start_at_round:
            attack_plan = dict.fromkeys(peer_ips, Attack.Benign)
            return attack_plan

        attack_plan = {}
        for peer_ip in peer_ips:
            if peer_ip in self.target_ip_list:
                attack_plan[peer_ip] = Attack.GeneralAttack
            else:
                attack_plan[peer_ip] = Attack.Benign
        return attack_plan

    def on_round_end(self, round_no: int):
        pass

    def handle_update(self, ip_address: str):
        pass

    def handle_data_request(self, message_data: str):
        pass
