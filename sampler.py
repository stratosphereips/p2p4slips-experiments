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
    def __init__(self, n):
        self.n = n
        self.peer_data = []

        for peer_no in range(0, n):
            peer_stats = []
            for remote_peer_no in range(0, n):
                history = [(0.5, 0.5)]
                peer_stats.append(history)
            self.peer_data.append(peer_stats)

    def process_attacks(self, attack_matrix):
        """
        For each peer, recompute his current score and confidence
        :param attack_matrix: a square matrix containing enum identifiers of attacks
        :return:
        """

        for peer_no in range(0, self.n):
            # this is a line that tells me how everyone will treat peer with id peer_no
            for remote_peer_no in range(0, self.n):
                if peer_no == remote_peer_no:
                    continue
                action = attack_matrix[remote_peer_no][peer_no]
                new_score_dif = get_score_sample(action)
                new_score_dif = get_diff_from_sample(new_score_dif)
                self.update_scores(peer_no, remote_peer_no, new_score_dif)

    def update_scores(self, peer_no, remote_peer_no, score_dif):
        history = self.peer_data[peer_no][remote_peer_no]
        last_score, last_confidence = history[-1]

        if peer_no == 1 and remote_peer_no == 0:
            # print(score_dif, real_score_dif, confidence_dif)
            k = 3

        new_score = min(1, max(last_score + score_dif, 0))
        real_score_dif = abs(last_score - new_score)
        confidence_dif = get_confidence_dif_from_score_dif(real_score_dif, new_score)
        new_confidence = min(1, max(last_confidence + confidence_dif, 0))
        if peer_no == 1 and remote_peer_no == 0:
            print(last_score, last_confidence, score_dif, real_score_dif, confidence_dif)
        new_score, new_confidence = clean_floats(new_score, new_confidence)
        self.peer_data[peer_no][remote_peer_no].append((new_score, new_confidence))

    def show_confidence_change_characteristics(self):
        X = list(range(-50, 50))
        X = [x/100 for x in X]
        Y = [get_confidence_dif_from_score_dif(x) for x in X]

        plt.plot(X, Y, color='g')
        plt.xlabel('Change in score')
        plt.ylabel('Suggested change in confidence')
        plt.show()

    def show_score_graphs(self, attacker_no, victim_no):
        history = self.peer_data[victim_no][attacker_no]

        score = [h[0] for h in history]
        confidence = [h[1] for h in history]
        timeline = list(range(0, len(history)))

        plt.plot(timeline, score, color='g')
        plt.plot(timeline, confidence, color='orange')
        plt.ylim(-0.05, 1.05)
        plt.xlabel('Algorithm rounds')
        plt.ylabel('Simulated IDS output')
        plt.title('Changes in score (green) and confidence (orange) in time')
        plt.show()