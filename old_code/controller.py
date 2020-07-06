import time
import copy

from dovecot import Dovecot
from evaluator import evaluate
from ipdb import IPDatabase
from peerwithstrategy import PeerWithStrategy
from slips_hub import SlipsHub
from utils import NetworkUpdate, publish_str_to_channel


class Controller:
    def __init__(self, peers: list, rounds: int, control_ips: list, observed_ips: list, timeouts: int = 5):
        self.peers = peers
        self.rounds = rounds
        self.timeouts = timeouts
        self.ipdb = IPDatabase(self.peers)
        self.control_ips = control_ips
        self.observed_ips = observed_ips
        # start pigeon simulator (runs in background and forwards messages, also has to process status changes)

        port_names = {}
        for peer in self.ipdb.peers:
            port_names[peer.port] = peer.name

        new_port_names = copy.deepcopy(port_names)
        self.dovecot = Dovecot(new_port_names, "p2p_pygo", "p2p_gopy")
        self.dovecot.start()

        # start slips simulator (doesn't actively listen to anything, but can be called in functions)
        self.hub = SlipsHub(self.ipdb, self.control_ips, self.observed_ips)
        self.attack_history = []

    def run_experiment(self):

        # wait so channels don't start sending data too early
        time.sleep(1)

        for rnd in range(0, self.rounds):

            # on round start
            for peer in self.peers:
                action, params = peer.on_round_start(rnd)
                self.process_round_start(peer, action, params)
            self.dovecot.notify_at_round_start()
            time.sleep(1)

            attacks = {}
            for peer in self.peers:
                attacks[peer.ipaddress] = peer.make_choice(rnd, self.ipdb.ips.keys())
            self.hub.run_detections(rnd, attacks)
            time.sleep(1)
            self.hub.collect_data(rnd)
            time.sleep(1)
            self.attack_history.append(attacks)

        evaluate(self.hub.observations, self.ipdb, self.rounds)
        self.hub.sampler.show_score_graphs(self.control_ips[0], self.observed_ips[0])

        time.sleep(1)
        for peer in self.peers:
            publish_str_to_channel("ip_info_change" + str(peer.port), "stop_process")
            self.dovecot.kill()

    def run_experiment_ids_only(self):

        # wait so channels don't start sending data too early
        time.sleep(1)
        for peer in self.peers:
            publish_str_to_channel("ip_info_change" + str(peer.port), "stop_process")
        time.sleep(1)

        for rnd in range(0, self.rounds):
            attacks = {}
            for peer in self.peers:
                attacks[peer.ipaddress] = peer.make_choice(rnd, self.ipdb.ips.keys())
            self.hub.run_detections_ids_only(rnd, attacks)

        self.hub.sampler.show_score_graphs(self.control_ips[0], self.observed_ips[0])

    def process_round_start(self, peer: PeerWithStrategy, action: NetworkUpdate, params: str):
        if action == NetworkUpdate.Stay:
            return
        if action == NetworkUpdate.JoinWithNewIp:
            self.ipdb.activate_peer_on_ip(peer, params)
            self.dovecot.peer_data_update(peer)
            return
        if action == NetworkUpdate.JoinWithSameIp:
            self.ipdb.activate_peer_on_ip(peer, peer.ipaddress)
            self.dovecot.peer_data_update(peer)
            return
        if action == NetworkUpdate.ChangeIp:
            self.ipdb.update_ip(peer, params)
            self.dovecot.peer_data_update(peer)
            return
        if action == NetworkUpdate.Leave:
            self.ipdb.deactivate_peer(peer)
            return

    def export_experiment_data(self):
        pass