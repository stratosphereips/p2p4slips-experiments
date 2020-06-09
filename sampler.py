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
        return np.random.beta(2, 8)
    if action == Attack.GeneralAttack:
        return np.random.beta(3, 1)
    if action == Attack.TargetedAttack:
        return np.random.beta(10, 1)
    if action == Attack.TargetedOnOthers:
        return np.random.beta(3, 3)


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
                new_score = get_score_sample(action)
                self.update_scores(peer_no, remote_peer_no, new_score)

    def update_scores(self, peer_no, remote_peer_no, score):
        history = self.peer_data[peer_no][remote_peer_no]
        last_score, last_confidence = history[-1]

        # get difference in scores
        dif = abs(score - last_score)

        # is the current score similar to the latest one?
        if dif < 0.1:
            # if yes, confidence should go up
            new_confidence = min(1, last_confidence + 0.1)
            # score should move to the average of the last two scores
            new_score = (score + last_score) / 2
        else:
            if dif > 0.2:
                # it the difference is high, confidence will be lowered
                new_confidence = max(0, last_confidence - 0.1)
            else:
                new_confidence = last_confidence
            if score < last_score:
                # if new data suggests a bad peer is good, higher priority is given to old data, to make bad reputation hard to lose
                new_score = (score + 2 * last_score) / 3
            else:
                new_score = (score + last_score) / 2

        new_score, new_confidence = clean_floats(new_score, new_confidence)
        self.peer_data[peer_no][remote_peer_no].append((new_score, new_confidence))

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