# the experiment class, that initializes all other things and calls iterations
from peerwithstrategy import PeerWithStrategy
from sampler import Sampler, Attack
from strategies.basic_strategy import be_nice, attack_all

if __name__ == '__main__':
    p1 = PeerWithStrategy(attack_all, 2)
    p2 = PeerWithStrategy(be_nice, 2)

    peers = [p1, p2]
    s = Sampler(2)
    for round in range(0, 10):
        attacks = []
        for peer in peers:
            attacks.append(peer.make_choice(round))
        s.process_attacks(attacks)
    k = 3