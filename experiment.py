# the experiment class, that initializes all other things and calls iterations
import time
from configparser import ConfigParser
from multiprocessing import Queue

from controller import Controller
from dovecot import Dovecot
from evaluator import evaluate
from experimental_printer import Printer
from ipdb import IPDatabase
from peerwithstrategy import PeerWithStrategy
from sampler import Sampler, Attack
from setups import get_basic_experiment
from slips_hub import SlipsHub
from strategies.strategy_benign import StrategyBeNice
from strategies.strategy_attack_all import StrategyAttackAll
from strategies.strategy_attack_target import StrategyAttackTarget

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

    ctrl = get_basic_experiment(output_process_queue, config)

    ctrl.run_experiment()

    # ctrl.hub.sampler.show_score_graphs("good_guy_1", "1.1.1.3")
    # s.show_score_graphs("good_guy_0", "attacker_targeting_p0")
    # s.show_score_graphs("good_guy_1", "all_attacker")
