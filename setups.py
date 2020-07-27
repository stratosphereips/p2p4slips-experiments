import configparser
import json
import os
import time
from multiprocessing import Queue

import matplotlib

from outputProcess import OutputProcess
from p2ptrust.testing.experiments.controller import Controller
from p2ptrust.testing.experiments.custom_devices.device import Device
from p2ptrust.testing.experiments.custom_devices.device_malicious import DeviceMalicious
from p2ptrust.testing.experiments.custom_devices.device_malicious_attack_target import DeviceMaliciousAttackTarget
from p2ptrust.testing.experiments.custom_devices.peer import Peer
from p2ptrust.testing.experiments.custom_devices.peer_liar_everyone_is_good import PeerLiarEveryoneIsGood
from p2ptrust.testing.experiments.custom_devices.peer_liar_target_is_bad import PeerLiarTargetIsBad
from p2ptrust.testing.experiments.evaluator import compute_detection
from p2ptrust.testing.experiments.output_processor import visualise_raw
from p2ptrust.testing.experiments.utils import init_experiment, prepare_experiments_dir
from slips.core.database import __database__


def get_default_config():
    cfg = configparser.ConfigParser()
    cfg.read_file(open("../../../../slips.conf"))
    return cfg


class Setups:
    def __init__(self, data_dir):
        self.setups = [self.run_test_experiments]
        self.data_dir = data_dir
        self.initialise_bad_peers = {"PeerLiarEveryoneIsGood": self.initialise_liar_everyone_is_good}

    def initialise_good_peer(self,
                             queue,
                             config,
                             data_dir,
                             peer_id,
                             port_base=6660,
                             ip_base="1.1.1.",
                             name_suffix="_good_peer"):
        p = Peer(output_queue=queue,
                 config=config,
                 data_dir=data_dir,
                 port=port_base + peer_id,
                 ip_address=ip_base + str(peer_id),
                 name=str(peer_id) + name_suffix)
        p.start()
        return p

    def initialise_liar_everyone_is_good(self,
                                         queue,
                                         config,
                                         data_dir,
                                         peer_id,
                                         params=None,
                                         port_base=6660,
                                         ip_base="1.1.1.",
                                         name_suffix="_peer_liar_everyone_is_good"):
        p = PeerLiarEveryoneIsGood(output_queue=queue,
                                   config=config,
                                   port=port_base + peer_id,
                                   data_dir=data_dir,
                                   ip_address=ip_base + str(peer_id),
                                   name=str(peer_id) + name_suffix)
        p.start()
        return p

    def initialise_malicious_device_with_target(self, attack_plan, peer_id):
        if attack_plan is None:
            targets = ["1.1.1.0"]
            attack_plan = {}
            for i in range(0, 20):
                attack_plan[i] = targets

        p = DeviceMaliciousAttackTarget(ip_address="1.1.1." + str(peer_id),
                                        name=str(peer_id) + "_device_malicious",
                                        is_good=False,
                                        victim_list=attack_plan)
        return p

    def initialise_malicious_device(self, peer_id):
        p = DeviceMalicious(ip_address="1.1.1." + str(peer_id),
                            name=str(peer_id) + "_device_malicious",
                            is_good=False)
        return p

    def initialise_benign_device(self, peer_id):
        p = Device(ip_address="1.1.1." + str(peer_id), name=str(peer_id) + "_device_benign")
        return p

    def get_experiment(self, id, output_process_queue, config):
        return self.setups[id](id, output_process_queue, config)

    def run_test_experiments(self, dir_prefix):
        observer_ips = ["1.1.1.0"]
        observed_ips = ["1.1.1.1"]
        base_dir = prepare_experiments_dir(dir_prefix, exp_name="_exp_0_tests")

        exp_id = 0

        ctrl = self.attack_parametrised(base_dir,
                                        exp_id=exp_id,
                                        n_good_peers=1,
                                        n_peers=2,
                                        n_rounds=3,
                                        bad_peer_type="PeerLiarEveryoneIsGood",
                                        attack_plan=None,
                                        experiment_suffix="_my_test_exp",
                                        observer_ips=observer_ips,
                                        observed_ips=observed_ips)
        ctrl.run_experiment()

    def run_2b(self, dir_prefix):
        base_dir = prepare_experiments_dir(dir_prefix, exp_name="_exp_2b")
        timestamp = str(time.time()) + "_exp2b"
        for peer_id in range(1, 10):
            config, queue, queue_thread, base_dir = init_experiment(base_dir)
            s = Setups(base_dir)
            attack_plan = {}
            for i in range(0, 20):
                targets = []
                if abs(peer_id - i) <= 1:
                    targets.append("1.1.1.0")
                attack_plan[i] = targets
            ctrl = s.attack_observer_no_peers(queue, config, exp_id=peer_id, attack_plan=attack_plan)
            ctrl.run_experiment_ids_only()
            queue_thread.kill()
            time.sleep(10)

    def keep_malicious_device_unblocked(self, output_process_queue, config: configparser.ConfigParser, n_peers=10,
                                        n_malicious_peers=3):
        # how many attackers does it take to keep communicating with a malicious device?
        # there are 10 peers total, 0-9 of them are malicious.
        # There is a malicious device that is attacking everyone except peer 1
        # after 10 round, this device starts attacking everyone.
        # there is also a benign device 11
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

            p.start()
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

        p = Device(ip_address="1.1.1." + str(n_peers + 1), name=str(n_peers + 1) + "_device_benign")
        devices.append(p)

        k = 3

        ctrl = Controller(devices, 20, ["1.1.1.0"], ["1.1.1.10", "1.1.1.11"], data_dir)
        return ctrl

    def attacker_targeting_different_amounts_of_peers(self, output_process_queue, config: configparser.ConfigParser,
                                                      n_peers=10,
                                                      n_victim_peers=3):
        data_dir = self.data_dir + str(n_victim_peers) + "_attacker_targeting_different_amounts_of_peers/"
        os.mkdir(data_dir)
        devices = []
        for peerid in range(0, n_peers):
            port = 6660 + peerid
            ip_address = "1.1.1." + str(peerid)
            # create a good peer
            p = Peer(output_queue=output_process_queue,
                     config=config,
                     data_dir=data_dir,
                     port=port,
                     ip_address=ip_address,
                     name=str(peerid) + "_peer_benign")

            p.start()
            devices.append(p)

        # the malicious device will attack everyone except 1.1.1.0 in the first part of the experiment
        targets_start = [device.ip_address for device in devices if device.port - 6660 >= n_peers - n_victim_peers]
        print(targets_start)

        targets_later = targets_start + ["1.1.1.0"]

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

        p = Device(ip_address="1.1.1." + str(n_peers + 1), name=str(n_peers + 1) + "_device_benign")
        devices.append(p)

        k = 3

        ctrl = Controller(devices, 20, ["1.1.1.0"], ["1.1.1.10", "1.1.1.11"], data_dir)
        return ctrl

    def badmouth_good_device(self, output_process_queue, config: configparser.ConfigParser, n_peers=10,
                             n_malicious_peers=3):
        # how many attackers does it take to block a benign device?
        # there are 10 peers total, 0-9 of them are malicious.
        # There is a malicious device that is attacking everyone except peer 1
        # after 10 round, this device starts attacking everyone.
        # there is also a benign device 11
        data_dir = self.data_dir + str(n_malicious_peers) + "_badmouth_good_device/"
        os.mkdir(data_dir)
        devices = []
        badmouthing_targets = ["1.1.1.11"]
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
                p = PeerLiarTargetIsBad(output_queue=output_process_queue,
                                        config=config,
                                        port=port,
                                        data_dir=data_dir,
                                        ip_address=ip_address,
                                        name=str(peerid) + "_peer_malicious",
                                        target_ips=badmouthing_targets)

            p.start()
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

        p = Device(ip_address="1.1.1." + str(n_peers + 1), name=str(n_peers + 1) + "_device_benign")
        devices.append(p)

        k = 3

        ctrl = Controller(devices, 20, ["1.1.1.0"], ["1.1.1.10", "1.1.1.11"], data_dir)
        return ctrl

    def attack_observer_no_peers(self, output_process_queue,
                                 config: configparser.ConfigParser,
                                 exp_id=0,
                                 attack_plan=None,
                                 exp_name="_keep_malicious_device_unblocked/"):
        # how many attackers does it take to keep communicating with a malicious device?
        # there are 10 peers total, 0-9 of them are malicious.
        # There is a malicious device that is attacking everyone except peer 1
        # after 10 round, this device starts attacking everyone.
        # there is also a benign device 11
        data_dir = self.data_dir + str(exp_id) + exp_name
        os.mkdir(data_dir)
        devices = []
        p = Peer(output_queue=output_process_queue,
                 config=config,
                 data_dir=data_dir,
                 port=6660,
                 ip_address="1.1.1.0",
                 name="0_peer_benign")
        p.start()
        devices.append(p)

        if attack_plan is None:
            targets = ["1.1.1.0"]
            attack_plan = {}
            for i in range(0, 20):
                attack_plan[i] = targets

        p = DeviceMaliciousAttackTarget(ip_address="1.1.1.10",
                                        name="10_device_malicious",
                                        is_good=False,
                                        victim_list=attack_plan)
        devices.append(p)

        p = Device(ip_address="1.1.1.11", name="11_device_benign")
        devices.append(p)
        ctrl = Controller(devices, 20, ["1.1.1.0"], ["1.1.1.10", "1.1.1.11"], data_dir)
        return ctrl

    def attack_parametrised(self,
                            dir_prefix: str,
                            exp_id=0,
                            n_good_peers=10,
                            n_peers=10,
                            n_rounds=20,
                            bad_peer_type="Something_here",
                            bad_peer_params=None,
                            attack_plan=None,
                            experiment_suffix="",
                            observer_ips=None,
                            observed_ips=None):

        config, queue, queue_thread, data_dir = init_experiment(dir_prefix, exp_id=exp_id, exp_suffix=experiment_suffix)

        devices = []

        # create good peers
        for peerid in range(0, n_good_peers):
            port = 6660 + peerid
            ip_address = "1.1.1." + str(peerid)
            p = Peer(output_queue=queue,
                     config=config,
                     data_dir=data_dir,
                     port=port,
                     ip_address=ip_address,
                     name=str(peerid) + "_peer_benign")

            p.start()
            devices.append(p)

        # create bad peers
        for peerid in range(n_good_peers, n_peers):
            port = 6660 + peerid
            ip_address = "1.1.1." + str(peerid)
            print(port, ip_address, bad_peer_type)
            p = self.initialise_bad_peers[bad_peer_type](queue=queue,
                                                         config=config,
                                                         data_dir=data_dir,
                                                         peer_id=peerid,
                                                         params=bad_peer_params)
            devices.append(p)

        devices.append(self.initialise_malicious_device_with_target(attack_plan, n_peers))
        devices.append(self.initialise_benign_device(n_peers + 1))

        if observer_ips is None:
            observer_ips = ["1.1.1.0"]

        if observed_ips is None:
            observed_ips = ["1.1.1.10", "1.1.1.11"]

        ctrl = Controller(devices, n_rounds, observer_ips, observed_ips, data_dir, queue_thread=queue_thread)
        return ctrl


def run_atdaop(n_peers=10):
    for i in range(1, n_peers):
        config, queue, queue_thread, base_dir = init_experiment(dirname, timestamp=timestamp)
        s = Setups(base_dir)
        ctrl = s.attacker_targeting_different_amounts_of_peers(queue, config, n_peers, i)
        ctrl.run_experiment()
        queue_thread.kill()
        time.sleep(10)


def run_kmdu(n_peers=10):
    for i in range(0, n_peers):
        config, queue, queue_thread, base_dir = init_experiment(dirname, timestamp=timestamp)
        s = Setups(base_dir)
        ctrl = s.keep_malicious_device_unblocked(queue, config, n_peers, i)
        ctrl.run_experiment()
        queue_thread.kill()
        time.sleep(10)


def run_attack_observer():
    config, queue, queue_thread, base_dir = init_experiment(dirname, timestamp=timestamp)
    s = Setups(base_dir)
    ctrl = s.attack_observer_no_peers(queue, config)
    ctrl.run_experiment_ids_only()
    queue_thread.kill()
    time.sleep(10)


def run_2b():
    dirname = "/home/dita/ownCloud/stratosphere/SLIPS/modules/p2ptrust/testing/experiments/experiment_data/experiments-"
    timestamp = str(time.time()) + "_exp2b"
    for peer_id in range(1, 10):
        config, queue, queue_thread, base_dir = init_experiment(dirname, timestamp=timestamp)
        s = Setups(base_dir)
        attack_plan = {}
        for i in range(0, 20):
            targets = []
            if abs(peer_id - i) <= 1:
                targets.append("1.1.1.0")
            attack_plan[i] = targets
        ctrl = s.attack_observer_no_peers(queue, config, exp_id=peer_id, attack_plan=attack_plan)
        ctrl.run_experiment_ids_only()
        queue_thread.kill()
        time.sleep(10)


def run_ips_sim_for_2b():
    exp_name = "_ips_sim"
    dirname = "/home/dita/ownCloud/stratosphere/SLIPS/modules/p2ptrust/testing/experiments/experiment_data/experiments-"
    timestamp = str(time.time())
    timestamp = "1595842634.7445016"
    # for peer_id in range(1, 10):
    #     config, queue, queue_thread, base_dir = init_experiments(dirname, timestamp=timestamp)
    #     s = Setups(base_dir)
    #     attack_plan = {}
    #     for i in range(0, 20):
    #         targets = []
    #         if abs(peer_id - i) <= 1:
    #             targets.append("1.1.1.0")
    #         attack_plan[i] = targets
    #     ctrl = s.attack_observer_no_peers(queue, config, exp_id=peer_id, attack_plan=attack_plan, exp_name=exp_name)
    #     ctrl.run_experiment_ids_only()
    #     queue_thread.kill()
    #     time.sleep(10)

    # a directory dirname was created, all data is there
    detections_in_peers = {}
    colors = {}
    ips = []
    cmap = matplotlib.cm.get_cmap('OrRd')
    for peer_id in range(1, 10):
        peer_ip = "1.1.1." + str(peer_id)
        colors[peer_ip] = cmap(peer_id / 15 + 0.3)
        detections_in_peers[peer_ip] = []
        ips.append(peer_ip)
        exp_file = dirname + timestamp + "/" + str(peer_id) + exp_name + "round_results.txt"
        with open(exp_file, "r") as f:
            data = json.load(f)
            rounds = sorted(list(map(int, data.keys())))
            for r in rounds:
                nscore, nconfidence, score, confidence = data[str(r)]["1.1.1.0"]["1.1.1.10"]
                detection = compute_detection(nscore, nconfidence, score, confidence, 1)
                detections_in_peers[peer_ip].append(detection)

    linewidths = {ip: 2 for ip in ips}
    alphas = {ip: 1 for ip in ips}
    labels = {ip: ip for ip in ips}

    visualise_raw(detections_in_peers, ips, rounds, colors, linewidths, alphas, labels)


if __name__ == '__main__':
    dirname = "/home/dita/ownCloud/stratosphere/SLIPS/modules/p2ptrust/testing/experiments/experiment_data/experiments-"
    s = Setups("")
    s.run_test_experiments(dirname)

    # run_ips_sim_for_2b()

    # for n_malicious_peers in range(1, 10):
    #     config, queue, queue_thread, base_dir = init_experiments(dirname, timestamp=timestamp)
    #     s = Setups(base_dir)
    #     print("Starting experiment", n_malicious_peers)
    #     ctrl = s.badmouth_good_device(queue, config, n_malicious_peers=n_malicious_peers, n_peers=10)
    #     # ctrl = s.get_test_experiment(0, queue, config)
    #     ctrl.run_experiment()
    #     queue_thread.kill()
    #     time.sleep(10)
    #     # SELECT * FROM main.reports r WHERE r.reporter_peerid LIKE '%malicious';
