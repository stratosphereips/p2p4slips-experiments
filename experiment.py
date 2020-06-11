# the experiment class, that initializes all other things and calls iterations
from experimental_printer import Printer
from peerwithstrategy import PeerWithStrategy
from sampler import Sampler, Attack
from strategies.basic_strategy import be_nice, attack_all, attack_p1

if __name__ == '__main__':
    printer = Printer()

    p0 = PeerWithStrategy(printer, "attacker_targeting_p1", attack_p1)
    p1 = PeerWithStrategy(printer, "good_guy_1", be_nice)
    p2 = PeerWithStrategy(printer, "good_guy_1", be_nice)
    p3 = PeerWithStrategy(printer, "all attacker", attack_all)

    peers = [p0, p1, p2, p3]
    peer_names = [p0.name, p1.name, p2.name, p3.name]
    s = Sampler(4)
    for round in range(0, 100):
        attacks = []
        for peer in peers:
            attacks.append(peer.make_choice(round, peer_names))
        s.process_attacks(attacks)

    s.show_score_graphs(0, 3)
