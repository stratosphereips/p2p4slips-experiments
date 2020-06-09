# a simple strategy
from sampler import Attack

def be_nice(round_no, number_of_peers):
    return [Attack.Benign] * number_of_peers


def attack_all(round_no, number_of_peers):
    return [Attack.GeneralAttack] * number_of_peers