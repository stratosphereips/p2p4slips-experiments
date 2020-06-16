from sampler import Attack
from strategies.basic_strategy import Strategy


class StrategyAttackAll(Strategy):

    def __init__(self):
        super().__init__()

    def on_round_start(self, round_no: int):
        pass

    def choose_round_behavior(self, round_no: int, peer_ids: list):
        attack_plan = dict.fromkeys(peer_ids, Attack.GeneralAttack)
        return attack_plan

    def on_round_end(self, round_no: int):
        pass