import os
import time
from configparser import ConfigParser
from multiprocessing import Queue
from slips.core.database import __database__
from outputProcess import OutputProcess
from p2ptrust.testing.experiments.setups import Setups


def get_default_config():
    cfg = ConfigParser()
    cfg.read_file(open("../../../../slips.conf"))
    return cfg


if __name__ == '__main__':
    config = get_default_config()
    output_process_queue = Queue()
    output_process_thread = OutputProcess(output_process_queue, 1, 1, config)
    output_process_thread.start()

    # Start the DB
    __database__.start(config)
    __database__.setOutputQueue(output_process_queue)

    base_dir = "/home/dita/ownCloud/stratosphere/SLIPS/modules/p2ptrust/testing/experiments/experiment_data/experiments-" + str(time.time()) + "/"
    os.mkdir(base_dir)
    setups = Setups(base_dir)
    experiment = setups.get_experiment(0, output_process_queue, config)
    # TODO: run the experiment
    experiment.run_experiment()
