# the experiment class, that initializes all other things and calls iterations
import time
from configparser import ConfigParser
from multiprocessing import Queue

import json

from controller import Controller
from dovecot import Dovecot
from evaluator import evaluate
from experimental_printer import Printer
from ipdb import IPDatabase
from peerwithstrategy import PeerWithStrategy
from sampler import Sampler, Attack
from setups import get_basic_experiment, get_idtrust_experiment_1
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


def save_exp_data(ctrl: Controller):
    round_results = ctrl.hub.observations
    attack_history = ctrl.attack_history
    data = {"round_results": round_results, "attack_history": attack_history}

    with open('data.txt', 'w') as outfile:
        json.dump(data, outfile)

if __name__ == '__main__':
    config = get_default_config()
    output_process_queue = Queue()
    output_process_thread = OutputProcess(output_process_queue, 1, 1, config)
    output_process_thread.start()

    # Start the DB
    __database__.start(config)
    __database__.setOutputQueue(output_process_queue)
    config = get_default_config()

    ctrl = get_idtrust_experiment_1(output_process_queue, config)

    ctrl.run_experiment()

    save_exp_data(ctrl)
