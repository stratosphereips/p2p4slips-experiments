from controller import Controller
from peerwithstrategy import PeerWithStrategy
from strategies.strategy_attack_all import StrategyAttackAll
from strategies.strategy_attack_target import StrategyAttackTarget
from strategies.strategy_benign import StrategyBeNice


def get_basic_experiment(output_process_queue, config):
    p0_strategy = StrategyBeNice()
    p0 = PeerWithStrategy(output_process_queue, "good_guy_0", p0_strategy, config, {"pigeon_port": 6660}, "1.1.1.0")

    p1_strategy = StrategyBeNice()
    p1 = PeerWithStrategy(output_process_queue, "good_guy_1", p1_strategy, config, {"pigeon_port": 6661}, "1.1.1.1")

    p2_strategy = StrategyAttackTarget("good_guy_0")
    p2 = PeerWithStrategy(output_process_queue, "attacker_targeting_p0", p2_strategy, config, {"pigeon_port": 6662}, "1.1.1.2")

    p3_strategy = StrategyAttackAll()
    p3 = PeerWithStrategy(output_process_queue, "all_attacker", p3_strategy, config, {"pigeon_port": 6663}, "1.1.1.3")

    peers = [p0, p1, p2, p3]

    ctrl = Controller(peers, 60)
    return ctrl