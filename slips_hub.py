from sampler import Sampler


class SlipsHub():
    def __init__(self, sampler: Sampler):
        self.sampler = sampler

    def run_detections(self, round, attacks: dict):
        self.sampler.process_attacks(round, attacks)

        for peer in attacks.keys():
            interactions = self.sampler.get_last_interactions_of_peer(peer)

    def process_interactions(self, peer_name: str, interactions: dict):
        for attacker_name in interactions.keys():
            last_score_confidence = self.get_score_confidence(peer_name, attacker_name)
        pass

    def get_score_confidence(self, peer_name, attacker_name):
        # oh noo, this is supposed to work on the ip-address level, not on peerid level :(
        pass
