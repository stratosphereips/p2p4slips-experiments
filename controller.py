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

    def run_experiment(self):
        # start pigeon simulator (runs in background and forwards messages, also has to process status changes)
        dovecot = Dovecot(self.ipdb)
        dovecot.start()

        # start slips simulator (doesn't actively listen to anything, but can be called in functions)
        hub = SlipsHub(self.ipdb)

        # wait so channels don't start sending data too early
        time.sleep(1)

        for rnd in range(0, 100):
            print(rnd)

            # on round start
            for peer in self.peers:
                print(peer)
                action, params = peer.on_round_start(rnd)
                self.process_round_start(peer, action, params)

            attacks = {}
            for peer in self.peers:
                attacks[peer.ipaddress] = peer.make_choice(rnd, self.ipdb.names.keys())
            hub.run_detections(rnd, attacks)
            time.sleep(1000)

        for rnd in range(0, self.rounds):

            pass

    def process_round_start(self, peer: PeerWithStrategy, action: NetworkUpdate, params: str):
        if action == NetworkUpdate.Stay:
            return
        if action == NetworkUpdate.JoinWithNewIp:
            self.ipdb.activate_peer_on_ip(peer, params)
        if action == NetworkUpdate.JoinWithSameIp:
            self.ipdb.activate_peer_on_ip(peer, peer.ipaddress)
        if action == NetworkUpdate.ChangeIp:
            self.ipdb.update_ip(peer, params)
        if action == NetworkUpdate.Leave:
            self.ipdb.deactivate_peer(peer)
