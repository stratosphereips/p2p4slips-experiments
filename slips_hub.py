import time

from ipdb import IPDatabase
from sampler import Sampler

# make imports from parent directory possible
import sys
import os
# we need to go all the way up, because modules import slips-wide stuff
from utils import update_slips_scores, publish_str_to_channel, get_network_score_confidence

sys.path.append(os.getcwd() + '/../../..')
from modules.p2ptrust.utils import get_ip_info_from_slips


class SlipsHub():
    def __init__(self, ipdb: IPDatabase, control_ips: list, observed_ips: list):
        self.sampler = Sampler()
        self.ipdb = ipdb
        self.control_ips = control_ips
        self.observed_ips = observed_ips
        self.observations = {}

    def run_detections(self, round, attacks: dict):
        self.sampler.process_attacks(round, attacks)

        victims = []
        for attack_list in attacks.values():
            victims.extend(attack_list.keys())

        victims = list(set(victims))
        for peer in victims:
            interactions = self.sampler.get_last_interactions_of_peer(peer)
            self.process_interactions(peer, interactions)
            time.sleep(1)

    def run_detections_ids_only(self, round, attacks: dict):
        self.sampler.process_attacks(round, attacks)

        victims = []
        for attack_list in attacks.values():
            victims.extend(attack_list.keys())

        victims = list(set(victims))
        for peer in victims:
            interactions = self.sampler.get_last_interactions_of_peer(peer)
            self.process_interactions(peer, interactions)

    def process_interactions(self, peer_ip: str, interactions: dict):
        port = self.ipdb.ips[peer_ip].port
        storage_name = "IPsInfo" + str(port)

        for attacker_ip_address, interaction in interactions.items():
            score, confidence = interaction
            saved_score, saved_confidence = self.get_score_confidence(attacker_ip_address, storage_name)
            if score == saved_score and confidence == saved_confidence:
                continue
            else:
                update_slips_scores("IPsInfo" + str(port), "ip_info_change" + str(port), attacker_ip_address, score, confidence)

    def get_score_confidence(self, attacker_ip_address, storage_name):
        return get_ip_info_from_slips(attacker_ip_address, storage_name)
    
    def collect_data(self, round: int):
        round_results = {}

        # for peer in list
        # send message to that peers request channel
        for peer_ip in self.control_ips:
            peer = self.ipdb.ips[peer_ip]
            request_channel = "p2p_data_request" + str(peer.port)
            for ip in self.observed_ips:
                publish_str_to_channel(request_channel, ip + " 0")
        
        # wait
        time.sleep(3)
        
        # collect data from that peers database
        for peer_ip in self.control_ips:
            round_results[peer_ip] = {}
            peer = self.ipdb.ips[peer_ip]
            storage_name = "IPsInfo" + str(peer.port)
            for ip in self.observed_ips:
                nscore, nconfidence = get_network_score_confidence(storage_name, ip)
                score, confidence = self.get_score_confidence(ip, storage_name)
                round_results[peer_ip][ip] = (nscore, nconfidence, score, confidence)
                print("HUUUUUUUU", nscore, nconfidence)

        self.observations[round] = round_results
