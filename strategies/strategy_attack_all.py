from sampler import Attack
from strategies.basic_strategy import Strategy


class StrategyAttackAll(Strategy):

    def __init__(self):
        super().__init__()
        self.override_handle_update = True
        self.override_handle_data_request = True

    def on_round_start(self, round_no: int):
        pass

    def choose_round_behavior(self, round_no: int, peer_ids: list):
        attack_plan = dict.fromkeys(peer_ids, Attack.GeneralAttack)
        return attack_plan

    def on_round_end(self, round_no: int):
        pass

    def handle_update(self, ip_address: str):
        print("I am an attacker, I don't check score updates")

    def handle_data_request(self, message_data: str):
        print("I am an attacker, I don't respond to queries")