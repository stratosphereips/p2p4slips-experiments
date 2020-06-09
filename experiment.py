# the experiment class, that initializes all other things and calls iterations
from peerwithstrategy import PeerWithStrategy
from sampler import Sampler, Attack
from strategies.basic_strategy import be_nice, attack_all, attack_p1

if __name__ == '__main__':
    p0 = PeerWithStrategy(attack_p1, 2)
    p1 = PeerWithStrategy(be_nice, 2)

    peers = [p0, p1]
    s = Sampler(2)
    for round in range(0, 300):
        attacks = []
        for peer in peers:
            attacks.append(peer.make_choice(round))
        s.process_attacks(attacks)

    s.show_score_graphs(0, 1)
