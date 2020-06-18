from sampler import Attack
from strategies.basic_strategy import Strategy
from utils import NetworkUpdate


class StrategyBeNice(Strategy):

    def __init__(self):
        super().__init__()

    def on_round_start(self, round_no: int):
        if round_no == 0:
            return NetworkUpdate.JoinWithSameIp, None
        return None, None

    def choose_round_behavior(self, round_no: int, peer_ids: list):
        attack_plan = dict.fromkeys(peer_ids, Attack.Benign)
        return attack_plan

    def on_round_end(self, round_no: int):
        pass
