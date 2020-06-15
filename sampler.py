# processes actions done by attackers, simulates slips by sampling from distributions, and sends reports about
# detections to all peers
import enum

import numpy as np
import matplotlib.pyplot as plt


class Attack(enum.Enum):
    Benign = 0
    GeneralAttack = 1
    TargetedAttack = 2
    TargetedOnOthers = 3


def get_score_sample(action: Attack):
    if action == Attack.Benign:
        return np.random.beta(20, 30)
    if action == Attack.GeneralAttack:
        return np.random.beta(2.5, 1)
    if action == Attack.TargetedAttack:
        return np.random.beta(10, 1)
    if action == Attack.TargetedOnOthers:
        return np.random.beta(3, 2.5)


def get_diff_from_sample(sample):
    score_dif = sample - 0.5
    return score_dif


def get_confidence_dif_from_score_dif_(score_dif):
    return min(pow((2 * score_dif) + 1, 2), pow((2 * score_dif) - 1, 2)) - 0.5

def get_confidence_dif_from_score_dif(score_dif, new_score):
    a = abs(score_dif)
    if a < 0.05:
        if new_score > 0.5:
            return 0.2
        else:
            return 0.05
    return -2 * a


def clean_floats(new_score, new_confidence):
    return round(new_score, 5), round(new_confidence, 5)


class Sampler:
    def __init__(self):
        self.peer_data = {}
        self.default_data = (0.5, 0.5)

    def process_attacks(self, round, attack_matrix: dict):
        """
        For each peer, recompute his current score and confidence
        :param attack_matrix: a square matrix containing enum identifiers of attacks
        :return:
        """

        for remote_peer_ip_address, outgoing_attacks in attack_matrix.items():
            # this is a line that tells me how everyone will treat peer with id peer_no
            for peer_name, action in outgoing_attacks.items():
                if remote_peer_ip_address == peer_name:
                    continue

                new_score_dif = get_score_sample(action)
                new_score_dif = get_diff_from_sample(new_score_dif)
                self.update_scores(round, peer_name, remote_peer_ip_address, new_score_dif)

    def update_scores(self, round, peer_name, remote_peer_ip_address, score_dif):
        last_score, last_confidence = self.get_last_score_confidence(peer_name, remote_peer_ip_address)

        new_score = min(1, max(last_score + score_dif, 0))
        real_score_dif = abs(last_score - new_score)
        confidence_dif = get_confidence_dif_from_score_dif(real_score_dif, new_score)
        new_confidence = min(1, max(last_confidence + confidence_dif, 0))
        if peer_name == 1 and remote_peer_ip_address == 0:
            print(last_score, last_confidence, score_dif, real_score_dif, confidence_dif)
        new_score, new_confidence = clean_floats(new_score, new_confidence)
        self.set_score_confidence(round, peer_name, remote_peer_ip_address, new_score, new_confidence)

    def set_score_confidence(self, round, peer_name, remote_peer_ip_address, score, confidence):
        if peer_name not in self.peer_data:
            self.peer_data[peer_name] = {}

        if remote_peer_ip_address not in self.peer_data[peer_name]:
            self.peer_data[peer_name][remote_peer_ip_address] = {"rounds": [], "data": []}

        self.peer_data[peer_name][remote_peer_ip_address]["rounds"].append(round)
        self.peer_data[peer_name][remote_peer_ip_address]["data"].append((score, confidence))

    def get_score_confidence_history(self, peer_name, remote_peer_ip_address):
        try:
            history = self.peer_data[peer_name][remote_peer_ip_address]
            rounds = history["rounds"]
            data = history["data"]
            return rounds, data
        except:
            return [-1], [(0.5, 0.5)]

    def get_last_score_confidence(self, peer_name, remote_peer_ip_address):
        rounds, data = self.get_score_confidence_history(peer_name, remote_peer_ip_address)
        return data[-1]

    def get_last_interactions_of_peer(self, peer_name):
        interactions = self.peer_data[peer_name]
        last_interactions = {}
        for attacker in interactions.keys():
            last_interaction = interactions[attacker]["data"][-1]
            last_interactions[attacker] = last_interaction
        return last_interactions

    def show_confidence_change_characteristics(self):
        X = list(range(-50, 50))
        X = [x/100 for x in X]
        Y = [get_confidence_dif_from_score_dif(x) for x in X]

        plt.plot(X, Y, color='g')
        plt.xlabel('Change in score')
        plt.ylabel('Suggested change in confidence')
        plt.show()

    def show_score_graphs(self, victim_name, remote_peer_ip_address):
        timeline, data = self.get_score_confidence_history(victim_name, remote_peer_ip_address)

        score = [h[0] for h in data]
        confidence = [h[1] for h in data]

        plt.plot(timeline, score, color='g')
        plt.plot(timeline, confidence, color='orange')
        plt.ylim(-0.05, 1.05)
        plt.xlabel('Algorithm rounds')
        plt.ylabel('Simulated IDS output')
        plt.title('Changes in score (green) and confidence (orange) in time')
        plt.show()