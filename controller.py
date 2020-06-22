import time

from dovecot import Dovecot
from ipdb import IPDatabase
from peerwithstrategy import PeerWithStrategy
from sampler import Sampler
from slips_hub import SlipsHub
from utils import NetworkUpdate


class Controller:
    def __init__(self, peers: list, rounds: int, timeouts: int = 5):
        self.peers = peers
        self.rounds = rounds
        self.timeouts = timeouts
        self.ipdb = IPDatabase(self.peers)
        # start pigeon simulator (runs in background and forwards messages, also has to process status changes)
        self.dovecot = Dovecot(self.ipdb)

        # start slips simulator (doesn't actively listen to anything, but can be called in functions)
        self.hub = SlipsHub(self.ipdb)

    def run_experiment(self):
        self.dovecot.start()

        # wait so channels don't start sending data too early
        time.sleep(1)

        for rnd in range(0, self.rounds):

            # on round start
            for peer in self.peers:
                action, params = peer.on_round_start(rnd)
                self.process_round_start(peer, action, params)
            self.dovecot.notify_at_round_start()

            attacks = {}
            for peer in self.peers:
                attacks[peer.ipaddress] = peer.make_choice(rnd, self.ipdb.names.keys())
            self.hub.run_detections(rnd, attacks)
            time.sleep(0.2)
            self.hub.collect_data()
            if rnd == 0:
                time.sleep(10)
            else:
                time.sleep(10000)

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
