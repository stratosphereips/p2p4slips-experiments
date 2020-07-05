from sampler import Attack
from strategies.basic_strategy import Strategy
from utils import NetworkUpdate


class StrategyAttackExp1(Strategy):

    def __init__(self, target_ip_list):
        super().__init__()
        self.target_ip_list = target_ip_list
        self.override_handle_update = True
        self.override_handle_data_request = True
        self.is_good = False
        self.do_p2p = True
        self.start_wide_attack_at_round = 15
        print("Starting liar strategy")

    def on_round_start(self, round_no: int):
        if round_no == 0:
            return NetworkUpdate.JoinWithSameIp, None
        return None, None

    def choose_round_behavior(self, round_no: int, peer_ips: list):
        if round_no >= self.start_wide_attack_at_round:
            attack_plan = dict.fromkeys(peer_ips, Attack.GeneralAttack)
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

    def respond_to_message_request(self, key, reporter):
        print("ALTERING REPORT DATA")
        self.go_listener.send_evaluation_to_go(key, 1, 1, reporter, self.pygo_channel)
