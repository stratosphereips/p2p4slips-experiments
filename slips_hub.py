from ipdb import IPDatabase
from sampler import Sampler

# make imports from parent directory possible
import sys
import os
# we need to go all the way up, because modules import slips-wide stuff
sys.path.append(os.getcwd() + '/../../..')
from modules.p2ptrust.utils import get_ip_info_from_slips

class SlipsHub():
    def __init__(self, sampler: Sampler, ipdb: IPDatabase):
        self.sampler = sampler
        self.ipdb = ipdb

    def run_detections(self, round, attacks: dict):
        self.sampler.process_attacks(round, attacks)

        for peer in attacks.keys():
            interactions = self.sampler.get_last_interactions_of_peer(peer)

    def process_interactions(self, peer_name: str, interactions: dict):
        for attacker_ip_address, interaction in interactions.items():
            score, confidence = interaction["data"][-1]
            saved_score, saved_confidence = self.get_score_confidence(peer_name, attacker_ip_address)
            # todo compare and send the new update
        pass

    def get_score_confidence(self, peer_name, attacker_ip_address):
        port = self.ipdb.get_peer_object(peer_name).port
        storage_name = "IPsInfo" + str(port)
        return get_ip_info_from_slips(attacker_ip_address, storage_name)