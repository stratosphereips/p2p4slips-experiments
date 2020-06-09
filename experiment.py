# the experiment class, that initializes all other things and calls iterations
from sampler import Sampler, Attack

if __name__ == '__main__':
    attacks = [[Attack.Benign]]
    s = Sampler(1)
    s.process_attacks(attacks)