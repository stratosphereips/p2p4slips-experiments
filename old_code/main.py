# the experiment class, that initializes all other things and calls iterations
import time
from configparser import ConfigParser
from multiprocessing import Queue

import json

from controller import Controller
from setups import Setups

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


def save_exp_data(ctrl: Controller, filename):
    round_results = ctrl.hub.observations
    attack_history = ctrl.attack_history
    data = {"round_results": round_results, "attack_history": attack_history}

    with open(filename + "data.txt", 'w') as outfile:
        json.dump(data, outfile)


if __name__ == '__main__':
    try:
        argv = sys.argv[1:]
        experiment_id = int(argv[0])
        data_dir = argv[1]
    except:
        print("No parameters provided, starting default settings")
        experiment_id = 1
        base_dir = "/home/dita/ownCloud/stratosphere/SLIPS/modules/p2ptrust/experiments-" + str(time.time()) + "/"
        os.mkdir(base_dir)
        data_dir = base_dir + str(experiment_id) + "/"
        os.mkdir(data_dir)

    print(data_dir)
    config = get_default_config()
    output_process_queue = Queue()
    output_process_thread = OutputProcess(output_process_queue, 1, 1, config)
    output_process_thread.start()

    # Start the DB
    __database__.start(config)
    __database__.setOutputQueue(output_process_queue)
    config = get_default_config()

    exp_setups = Setups(data_dir)
    ctrl = exp_setups.get_experiment(experiment_id, output_process_queue, config)
    ctrl.run_experiment()
    output_process_thread.kill()

    save_exp_data(ctrl, data_dir)
