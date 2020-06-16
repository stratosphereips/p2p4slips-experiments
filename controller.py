import time

from dovecot import Dovecot
from ipdb import IPDatabase
from sampler import Sampler
from slips_hub import SlipsHub


class Controller:
    def __init__(self, peers: list, rounds: int, timeouts: int = 5):
        self.peers = peers
        self.rounds = rounds
        self.timeouts = timeouts
        self.ipdb = IPDatabase(self.peers)

    def run_experiment(self):
        dovecot = Dovecot(self.ipdb)
        dovecot.start()
        for p in self.peers:
            print(p.name)
            self.ipdb.set_peer_object(p.name, p)
            self.ipdb.set_custom_ip(p.name, p.ipaddress)

        sampler = Sampler()
        hub = SlipsHub(sampler, self.ipdb)
        time.sleep(1)

        for round in range(0, 100):
            attacks = {}
            for peer in self.peers:
                attacks[peer.ipaddress] = peer.make_choice(round, self.ipdb.names.keys())
            hub.run_detections(round, attacks)
            time.sleep(1000)

        for rnd in range(0, self.rounds):

            pass
