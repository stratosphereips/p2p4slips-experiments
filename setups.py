import configparser
import os
import time
from multiprocessing import Queue

from outputProcess import OutputProcess
from p2ptrust.testing.experiments.controller import Controller
from p2ptrust.testing.experiments.custom_devices.device_malicious import DeviceMalicious
from p2ptrust.testing.experiments.custom_devices.device_malicious_attack_target import DeviceMaliciousAttackTarget
from p2ptrust.testing.experiments.custom_devices.peer import Peer
from p2ptrust.testing.experiments.custom_devices.peer_liar_everyone_is_good import PeerLiarEveryoneIsGood
from slips.core.database import __database__


def get_default_config():
    cfg = configparser.ConfigParser()
    cfg.read_file(open("../../../../slips.conf"))
    return cfg


class Setups:
    def __init__(self, data_dir):
        self.setups = [self.get_test_experiment]
        self.data_dir = data_dir

    def get_experiment(self, id, output_process_queue, config):
        return self.setups[id](id, output_process_queue, config)

    def get_test_experiment(self, identifier: int, output_process_queue, config: configparser.ConfigParser):
        data_dir = self.data_dir + str(identifier) + "/"
        os.mkdir(data_dir)
        p0 = Peer(output_queue=output_process_queue,
                  config=config,
                  data_dir=data_dir,
                  port=6660,
                  ip_address="1.1.1.0",
                  name="0_peer_benign")
        p0.start()

        # later, this device will be malicious
        p1 = DeviceMalicious(ip_address="1.1.1.1", name="1_device_malicious", is_good=False)

        p2 = PeerLiarEveryoneIsGood(output_queue=output_process_queue,
                                    config=config,
                                    port=6662,
                                    data_dir=data_dir,
                                    ip_address="1.1.1.2",
                                    name="2_peer_malicious")
        p2.start()

        peers = [p0, p1, p2]

        ctrl = Controller(peers, 3, ["1.1.1.0"], ["1.1.1.1"], data_dir)
        return ctrl

    def keep_malicious_device_unblocked(self, output_process_queue, config: configparser.ConfigParser, n_peers=10, n_malicious_peers=3):
        # how many attackers does it take to keep communicating with a malicious device?
        # there are 10 peers total, 0-9 of them are malicious.
        # There is a malicious device that is attacking everyone except peer 1
        # after 10 round, this device starts attacking everyone.
        data_dir = self.data_dir + str(n_malicious_peers) + "_keep_malicious_device_unblocked/"
        os.mkdir(data_dir)
        devices = []
        n_good_peers = n_peers - n_malicious_peers
        for peerid in range(0, n_peers):
            port = 6660 + peerid
            ip_address = "1.1.1." + str(peerid)
            if peerid < n_good_peers:
                # create a good peer
                p = Peer(output_queue=output_process_queue,
                         config=config,
                         data_dir=data_dir,
                         port=port,
                         ip_address=ip_address,
                         name=str(peerid) + "_peer_benign")
            else:
                # create a bad peer
                p = PeerLiarEveryoneIsGood(output_queue=output_process_queue,
                                           config=config,
                                           port=port,
                                           data_dir=data_dir,
                                           ip_address=ip_address,
                                           name=str(peerid) + "_peer_malicious")
            devices.append(p)

        # the malicious device will attack everyone except 1.1.1.0 in the first part of the experiment
        targets_start = [device.ip_address for device in devices]
        targets_start.remove("1.1.1.0")

        # later in the experiment, the device will attack everyone
        targets_later = [device.ip_address for device in devices]

        attack_plan = {}
        for i in range(0, 10):
            attack_plan[i] = targets_start
        for i in range(10, 20):
            attack_plan[i] = targets_later

        p = DeviceMaliciousAttackTarget(ip_address="1.1.1." + str(n_peers),
                                        name=str(n_peers) + "_device_malicious",
                                        is_good=False,
                                        victim_list=attack_plan)
        devices.append(p)
        k = 3

        ctrl = Controller(devices, 20, ["1.1.1.0"], ["1.1.1.1"], data_dir)
        return ctrl


if __name__ == '__main__':
    config = get_default_config()
    output_process_queue = Queue()
    output_process_thread = OutputProcess(output_process_queue, 1, 1, config)
    output_process_thread.start()

    # Start the DB
    __database__.start(config)
    __database__.setOutputQueue(output_process_queue)
    base_dir = "/home/dita/ownCloud/stratosphere/SLIPS/modules/p2ptrust/testing/experiments/experiment_data/experiments-" + str(
        time.time()) + "/"
    os.mkdir(base_dir)
    s = Setups(base_dir)
    ctrl = s.keep_malicious_device_unblocked(output_process_queue, config)
    ctrl.run_experiment()
