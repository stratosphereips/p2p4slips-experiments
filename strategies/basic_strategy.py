# a simple strategy
from sampler import Attack

def be_nice(round_no, number_of_peers):
    return [Attack.Benign] * number_of_peers


def attack_all(round_no, number_of_peers):
    return [Attack.GeneralAttack] * number_of_peers


def attack_p1(round_no, number_of_peers):
    if round_no < 200:
        attack_plan = [Attack.TargetedOnOthers] * number_of_peers
        attack_plan[1] = Attack.TargetedAttack
    else:
        attack_plan = [Attack.Benign] * number_of_peers
    return attack_plan