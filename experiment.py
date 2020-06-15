# the experiment class, that initializes all other things and calls iterations
from configparser import ConfigParser
from multiprocessing import Queue

from dovecot import Dovecot
from experimental_printer import Printer
from ipdb import IPDatabase
from peerwithstrategy import PeerWithStrategy
from sampler import Sampler, Attack
from strategies.basic_strategy import StrategyAttackAll, StrategyAttackTarget, StrategyBeNice

# make imports from parent directory possible
import sys
import os
# we need to go all the way up, because modules import slips-wide stuff
sys.path.append(os.getcwd() + '/../../..')
from slips.core.database import __database__
from outputProcess import OutputProcess

def get_default_config():
    cfg = ConfigParser()
    cfg.read_file(open("../../../slips.conf"))
    return cfg

if __name__ == '__main__':
    config = get_default_config()
    output_process_queue = Queue()
    output_process_thread = OutputProcess(output_process_queue, 1, 1, config)
    output_process_thread.start()

    # Start the DB
    __database__.start(config)
    __database__.setOutputQueue(output_process_queue)
    config = get_default_config()


    p0_strategy = StrategyBeNice()
    p0 = PeerWithStrategy(output_process_queue, "good_guy_0", p0_strategy, config, {"pigeon_port": 6660}, "1.1.1.0")

    p1_strategy = StrategyBeNice()
    p1 = PeerWithStrategy(output_process_queue, "good_guy_1", p1_strategy, config, {"pigeon_port": 6661}, "1.1.1.1")

    p2_strategy = StrategyAttackTarget("good_guy_0")
    p2 = PeerWithStrategy(output_process_queue, "attacker_targeting_p0", p2_strategy, config, {"pigeon_port": 6662}, "1.1.1.2")

    p3_strategy = StrategyAttackAll()
    p3 = PeerWithStrategy(output_process_queue, "all_attacker", p3_strategy, config, {"pigeon_port": 6663}, "1.1.1.3")

    peers = [p0, p1, p2, p3]
    peer_names = [p0.name, p1.name, p2.name, p3.name]

    dovecot = Dovecot({p0.name: 6660, p1.name: 6661, p2.name: 6662, p3.name:6663})
    dovecot.start()
    ipdb = IPDatabase()
    for p in peers:
        ipdb.set_custom_ip(p.name, p.ipaddress)

    s = Sampler(4)
    for round in range(0, 100):
        attacks = {}
        for peer in peers:
            attacks[peer.ipaddress] = peer.make_choice(round, peer_names)
        s.process_attacks(round, attacks)

    # s.show_score_graphs("good_guy_0", "attacker_targeting_p0")
    s.show_score_graphs("good_guy_1", "all_attacker")
