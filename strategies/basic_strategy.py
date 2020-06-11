# a simple strategy
from sampler import Attack

class Strategy:
    def __init__(self):
        pass

    def on_round_start(self, round_no: int):
        raise NotImplementedError

    def choose_round_behavior(self, round_no: int, peer_ids: list):
        raise NotImplementedError

    def on_round_end(self, round_no: int):
        raise NotImplementedError


class StrategyAttackTarget(Strategy):

    def __init__(self, target_name):
        super().__init__()
        self.target_name = target_name

    def on_round_start(self, round_no: int):
        pass

    def choose_round_behavior(self, round_no: int, peer_ids: list):
        attack_plan = dict.fromkeys(peer_ids, Attack.Benign)
        if round_no < 20 and self.target_name in peer_ids:
            attack_plan[self.target_name] = Attack.TargetedAttack
        return attack_plan

    def on_round_end(self, round_no: int):
        pass

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

class StrategyBeNice(Strategy):

    def __init__(self):
        super().__init__()

    def on_round_start(self, round_no: int):
        pass

    def choose_round_behavior(self, round_no: int, peer_ids: list):
        attack_plan = dict.fromkeys(peer_ids, Attack.Benign)
        return attack_plan

    def on_round_end(self, round_no: int):
        pass

