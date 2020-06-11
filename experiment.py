# the experiment class, that initializes all other things and calls iterations
from experimental_printer import Printer
from peerwithstrategy import PeerWithStrategy
from sampler import Sampler, Attack
from strategies.basic_strategy import StrategyAttackAll, StrategyAttackTarget, StrategyBeNice

if __name__ == '__main__':
    printer = Printer()

    p0_strategy = StrategyBeNice()
    p0 = PeerWithStrategy(printer, "good_guy_0", p0_strategy)

    p1_strategy = StrategyBeNice()
    p1 = PeerWithStrategy(printer, "good_guy_1", p1_strategy)

    p2_strategy = StrategyAttackTarget("good_guy_0")
    p2 = PeerWithStrategy(printer, "attacker_targeting_p0", p2_strategy)

    p3_strategy = StrategyAttackAll()
    p3 = PeerWithStrategy(printer, "all_attacker", p3_strategy)

    peers = [p0, p1, p2, p3]
    peer_names = [p0.name, p1.name, p2.name, p3.name]
    s = Sampler(4)
    for round in range(0, 100):
        attacks = {}
        for peer in peers:
            attacks[peer.name] = peer.make_choice(round, peer_names)
        s.process_attacks(round, attacks)

    # s.show_score_graphs("good_guy_0", "attacker_targeting_p0")
    s.show_score_graphs("good_guy_1", "all_attacker")
