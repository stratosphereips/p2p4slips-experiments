import configparser
import json
import os
import time
import matplotlib

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


def get_default_config():
    cfg = configparser.ConfigParser()
    cfg.read_file(open("../../../../slips.conf"))
    return cfg


def get_two_part_attack_plan(n_rounds, n_peers):
    attack_plan = {}
    for i in range(0, n_rounds):
        attack_plan[i] = []
        for peer_id in range(1, n_peers):
            attack_plan[i].append("1.1.1." + str(peer_id))
        if i >= (n_rounds / 2):
            attack_plan[i].append("1.1.1.0")
    return attack_plan


def get_staggered_attack_plan(n_rounds, n_peers):
    # prepare attack plan for the malicious device
    attack_plan = {}

    # the attack plan has a separate layout for each round
    for rnd in range(0, n_rounds):
        targets = []
        for peer_id in range(1, n_peers):
            # a peer will be attacked if it's id is close to the round
            if abs(peer_id - rnd) <= 1:
                targets.append("1.1.1." + str(peer_id))
        attack_plan[rnd] = targets

    # the observer is attacked in the second half of the experiment
    for rnd in range(int(round(n_rounds / 2)), n_rounds):
        attack_plan[rnd].append("1.1.1.0")

    return attack_plan


def get_attack_plan_with_given_victim_count(n_rounds, n_victims):
    targets = []
    for i in range(0, n_victims):
        victim_ip = "1.1.1." + str(i + 1)
        targets.append(victim_ip)

    # the attack plan has a the same layout for each round
    attack_plan = {}
    for rnd in range(0, n_rounds):
        attack_plan[rnd] = targets
        if rnd > n_rounds/2:
            attack_plan[rnd].append("1.1.1.0")

    return attack_plan


def initialise_good_peer(queue,
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


def initialise_liar_everyone_is_good(queue,
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


def initialise_malicious_peer_badmouth_target(queue,
                                              config,
                                              data_dir,
                                              peer_id,
                                              params=None,
                                              port_base=6660,
                                              ip_base="1.1.1.",
                                              name_suffix="_peer_barmouth_target"):
    if params is None:
        params = []

    p = PeerLiarTargetIsBad(output_queue=queue,
                            config=config,
                            port=port_base + peer_id,
                            data_dir=data_dir,
                            ip_address=ip_base + str(peer_id),
                            name=str(peer_id) + name_suffix,
                            target_ips=params)
    p.start()
    return p


def initialise_malicious_device_with_target(attack_plan, peer_id):
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


def initialise_malicious_device(peer_id):
    p = DeviceMalicious(ip_address="1.1.1." + str(peer_id),
                        name=str(peer_id) + "_device_malicious",
                        is_good=False)
    return p


def initialise_benign_device(peer_id):
    p = Device(ip_address="1.1.1." + str(peer_id), name=str(peer_id) + "_device_benign")
    return p


class Setups:
    def __init__(self, data_dir):
        self.setups = [self.run_test_experiments]
        self.data_dir = data_dir
        self.initialise_bad_peers = {"PeerLiarEveryoneIsGood": initialise_liar_everyone_is_good,
                                     "PeerBadmouthTarget": initialise_malicious_peer_badmouth_target}

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

    def run_2a(self, dir_prefix):
        base_dir = prepare_experiments_dir(dir_prefix, exp_name="_exp_2a")

        attack_plan = get_two_part_attack_plan(n_rounds=20, n_peers=10)

        exp_id = 0
        ctrl = self.attack_parametrised(base_dir,
                                        exp_id=exp_id,
                                        n_good_peers=10,
                                        n_peers=10,
                                        n_rounds=20,
                                        attack_plan=attack_plan,
                                        experiment_suffix="")
        ctrl.run_experiment()

    def run_2b(self, dir_prefix):
        base_dir = prepare_experiments_dir(dir_prefix, exp_name="_exp_2b")

        attack_plan = get_staggered_attack_plan(n_rounds=20, n_peers=10)
        exp_id = 0
        ctrl = self.attack_parametrised(base_dir,
                                        exp_id=exp_id,
                                        n_good_peers=10,
                                        n_peers=10,
                                        n_rounds=20,
                                        attack_plan=attack_plan,
                                        experiment_suffix="")
        ctrl.run_experiment()

    def run_2c(self, dir_prefix):
        # malicious device attacks different amounts of peers, no malicious peers are present

        base_dir = prepare_experiments_dir(dir_prefix, exp_name="_exp_2c")

        for n_victims in range(1, 10):
            attack_plan = get_attack_plan_with_given_victim_count(n_rounds=20, n_victims=n_victims)
            ctrl = self.attack_parametrised(base_dir,
                                            exp_id=n_victims,
                                            n_good_peers=10,
                                            n_peers=10,
                                            n_rounds=20,
                                            attack_plan=attack_plan,
                                            experiment_suffix="")
            ctrl.run_experiment()
            time.sleep(5)

    def run_3a(self, dir_prefix):
        # malicious peers are praising the malicious device

        base_dir = prepare_experiments_dir(dir_prefix, exp_name="_exp_3a")

        # prepare attack plan for the malicious device
        attack_plan = get_two_part_attack_plan(n_rounds=20, n_peers=10)

        for n_good_peers in range(1, 10):
            ctrl = self.attack_parametrised(base_dir,
                                            exp_id=n_good_peers,
                                            n_good_peers=n_good_peers,
                                            n_peers=10,
                                            n_rounds=20,
                                            attack_plan=attack_plan,
                                            bad_peer_type="PeerLiarEveryoneIsGood",
                                            experiment_suffix="")
            ctrl.run_experiment()
            time.sleep(5)

    def run_3b(self, dir_prefix):
        # malicious peers are praising the malicious device

        base_dir = prepare_experiments_dir(dir_prefix, exp_name="_exp_3b")

        # prepare attack plan for the malicious device
        attack_plan = get_staggered_attack_plan(n_rounds=20, n_peers=10)

        for n_good_peers in range(1, 10):
            ctrl = self.attack_parametrised(base_dir,
                                            exp_id=n_good_peers,
                                            n_good_peers=n_good_peers,
                                            n_peers=10,
                                            n_rounds=20,
                                            attack_plan=attack_plan,
                                            bad_peer_type="PeerLiarEveryoneIsGood",
                                            experiment_suffix="")
            ctrl.run_experiment()
            time.sleep(5)

    def run_3c(self, dir_prefix):
        # malicious peers are praising the malicious device

        base_dir = prepare_experiments_dir(dir_prefix, exp_name="_exp_3c")

        for n_good_peers in range(1, 10):
            for n_victims in range(1, 10):
                exp_id = 10*n_good_peers + n_victims
                attack_plan = get_attack_plan_with_given_victim_count(n_rounds=20, n_victims=n_victims)
                ctrl = self.attack_parametrised(base_dir,
                                                exp_id=exp_id,
                                                n_good_peers=n_good_peers,
                                                n_peers=10,
                                                n_rounds=20,
                                                attack_plan=attack_plan,
                                                bad_peer_type="PeerLiarEveryoneIsGood",
                                                experiment_suffix="")
                ctrl.run_experiment()
                time.sleep(5)

    def run_4a(self, dir_prefix):
        # badmouthing
        # no need to run this on more reporters

        base_dir = prepare_experiments_dir(dir_prefix, exp_name="_exp_4a")

        # prepare attack plan for the malicious device
        attack_plan = get_two_part_attack_plan(n_rounds=20, n_peers=10)
        badmouthing_targets = ["1.1.1.11"]

        for n_good_peers in range(1, 10):
            ctrl = self.attack_parametrised(base_dir,
                                            exp_id=n_good_peers,
                                            n_good_peers=n_good_peers,
                                            n_peers=10,
                                            n_rounds=20,
                                            attack_plan=attack_plan,
                                            bad_peer_type="PeerBadmouthTarget",
                                            bad_peer_params=badmouthing_targets,
                                            experiment_suffix="")
            ctrl.run_experiment()
            time.sleep(5)

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

        devices.append(initialise_malicious_device_with_target(attack_plan, n_peers))
        devices.append(initialise_benign_device(n_peers + 1))

        if observer_ips is None:
            observer_ips = ["1.1.1.0"]

        if observed_ips is None:
            observed_ips = ["1.1.1.10", "1.1.1.11"]

        ctrl = Controller(devices, n_rounds, observer_ips, observed_ips, data_dir, queue_thread=queue_thread)
        return ctrl


def run_ips_sim_for_2b():
    exp_name = "_ips_sim"
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
                net_score, net_confidence, score, confidence = data[str(r)]["1.1.1.0"]["1.1.1.10"]
                detection = compute_detection(net_score, net_confidence, score, confidence, 1)
                detections_in_peers[peer_ip].append(detection)

    line_widths = {ip: 2 for ip in ips}
    alphas = {ip: 1 for ip in ips}
    labels = {ip: ip for ip in ips}

    visualise_raw(detections_in_peers, ips, rounds, colors, line_widths, alphas, labels)


if __name__ == '__main__':
    dirname = "/home/dita/ownCloud/stratosphere/SLIPS/modules/p2ptrust/testing/experiments/experiment_data/experiments-"
    s = Setups("")
    # s.run_test_experiments(dirname)
    # s.run_2b(dirname)
    s.run_2a(dirname)
    # s.run_3(dirname)
    # s.run_4(dirname)
