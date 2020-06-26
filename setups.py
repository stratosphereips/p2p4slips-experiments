from controller import Controller
from peerwithstrategy import PeerWithStrategy
from strategies.peer_lie_everyone_is_good import PeerLiarEveryoneIsGood
from strategies.strategy_attack_all import StrategyAttackAll
from strategies.strategy_attack_target import StrategyAttackTarget
from strategies.strategy_attack_target_list import StrategyAttackTargetList
from strategies.strategy_attacker_random import StrategyAttackRandomAndLie
from strategies.strategy_benign_peer import StrategyBenignPeer


class Setups:
    def __init__(self, data_dir):
        self.setups = [self.can_we_warn_A,
                       self.will_they_block_benign_device_2,
                       self.will_they_block_benign_device_4]
        self.data_dir = data_dir

    def get_experiment(self, id, output_process_queue, config):
        return self.setups[id](output_process_queue, config)

    def get_basic_experiment(self, output_process_queue, config):
        p0_strategy = StrategyBenignPeer()
        p0 = PeerWithStrategy(output_process_queue, "good_guy_0", p0_strategy, config, {"pigeon_port": 6660}, "1.1.1.0", self.data_dir)

        p1_strategy = StrategyBenignPeer()
        p1 = PeerWithStrategy(output_process_queue, "good_guy_1", p1_strategy, config, {"pigeon_port": 6661}, "1.1.1.1", self.data_dir)

        p2_strategy = StrategyAttackTarget("1.1.1.0")
        p2 = PeerWithStrategy(output_process_queue, "attacker_targeting_p0", p2_strategy, config, {"pigeon_port": 6662}, "1.1.1.2", self.data_dir)

        p3_strategy = StrategyAttackAll()
        p3 = PeerWithStrategy(output_process_queue, "all_attacker", p3_strategy, config, {"pigeon_port": 6663}, "1.1.1.3", self.data_dir)

        peers = [p0, p1, p2, p3]

        ctrl = Controller(peers, 5, ["1.1.1.0"], ["1.1.1.3"])
        return ctrl

    def can_we_warn_A(self, output_process_queue, config):
        # a collective of peers is attacked by peer 10. Peer 0 is the only one not attacked. The group should warn 0.

        peers = []
        good_peer_ips = []

        # the good peers:
        for i in range(0, 10):
            name = "good_guy_" + str(i)
            ip = "1.1.1." + str(i)
            port = 6660 + i
            strategy = StrategyBenignPeer()
            peer = PeerWithStrategy(output_process_queue, name, strategy, config, {"pigeon_port": port}, ip, self.data_dir)
            peers.append(peer)
            good_peer_ips.append(ip)

        i = 10
        name = "bad_guy_" + str(i)
        ip = "1.1.1." + str(i)
        port = 6660 + i
        strategy = StrategyAttackTargetList(good_peer_ips[1:])
        peer = PeerWithStrategy(output_process_queue, name, strategy, config, {"pigeon_port": port}, ip, self.data_dir)
        peers.append(peer)
        ctrl = Controller(peers, 30, ["1.1.1.0"], ["1.1.1.10"])
        return ctrl

    def will_they_block_benign_device_2(self, output_process_queue, config):

        peers = []
        good_peer_ips = []

        # the good peers:
        for i in range(0, 5):
            name = "good_guy_" + str(i)
            ip = "1.1.1." + str(i)
            port = 6660 + i
            strategy = StrategyBenignPeer()
            peer = PeerWithStrategy(output_process_queue, name, strategy, config, {"pigeon_port": port}, ip, self.data_dir)
            peers.append(peer)
            good_peer_ips.append(ip)

        i = 6
        name = "good_device_" + str(i)
        ip = "1.1.1." + str(i)
        port = 6660 + i
        strategy = StrategyAttackTargetList(good_peer_ips[1:])
        peer = PeerWithStrategy(output_process_queue, name, strategy, config, {"pigeon_port": port}, ip, self.data_dir)
        peers.append(peer)

        # the bad peers:
        for i in range(7, 9):
            name = "bad_guy_" + str(i)
            ip = "1.1.1." + str(i)
            port = 6660 + i
            strategy = PeerLiarEveryoneIsGood()
            peer = PeerWithStrategy(output_process_queue, name, strategy, config, {"pigeon_port": port}, ip, self.data_dir)
            strategy.set_module_process(peer)
            peers.append(peer)

        ctrl = Controller(peers, 30, ["1.1.1.0"], ["1.1.1.6"])
        return ctrl

    def will_they_block_benign_device_4(self, output_process_queue, config):

        peers = []
        good_peer_ips = []

        # the good peers:
        for i in range(0, 5):
            name = "good_guy_" + str(i)
            ip = "1.1.1." + str(i)
            port = 6660 + i
            strategy = StrategyBenignPeer()
            peer = PeerWithStrategy(output_process_queue, name, strategy, config, {"pigeon_port": port}, ip, self.data_dir)
            peers.append(peer)
            good_peer_ips.append(ip)

        i = 6
        name = "good_device_" + str(i)
        ip = "1.1.1." + str(i)
        port = 6660 + i
        strategy = StrategyAttackTargetList(good_peer_ips[1:])
        peer = PeerWithStrategy(output_process_queue, name, strategy, config, {"pigeon_port": port}, ip, self.data_dir)
        peers.append(peer)

        # the bad peers:
        for i in range(7, 11):
            name = "bad_guy_" + str(i)
            ip = "1.1.1." + str(i)
            port = 6660 + i
            strategy = PeerLiarEveryoneIsGood()
            peer = PeerWithStrategy(output_process_queue, name, strategy, config, {"pigeon_port": port}, ip, self.data_dir)
            strategy.set_module_process(peer)
            peers.append(peer)

        ctrl = Controller(peers, 30, ["1.1.1.0"], ["1.1.1.6"])
        return ctrl

    def get_idtrust_experiment_1(self, output_process_queue, config):
        # 15 good peers, 5 bad peers reporting inverse stuff
        peers = []
        good_peer_ips = []

        # the good peers:
        for i in range(0, 15):
            name = "good_guy_" + str(i)
            ip = "1.1.1." + str(i)
            port = 6660 + i
            strategy = StrategyBenignPeer()
            peer = PeerWithStrategy(output_process_queue, name, strategy, config, {"pigeon_port": port}, ip, self.data_dir)
            peers.append(peer)
            good_peer_ips.append(ip)

        # the bad peers:
        for i in range(15, 20):
            name = "bad_guy_" + str(i)
            ip = "1.1.1." + str(i)
            port = 6660 + i
            strategy = StrategyAttackRandomAndLie()
            peer = PeerWithStrategy(output_process_queue, name, strategy, config, {"pigeon_port": port}, ip, self.data_dir)
            strategy.set_good_peer_list(good_peer_ips)
            strategy.set_module_process(peer)
            peers.append(peer)

        ctrl = Controller(peers, 2, ["1.1.1.0"], ["1.1.1.15"])
        return ctrl

    def get_idtrust_experiment_2(self, output_process_queue, config):
        peers = []
        good_peer_ips = []

        # the good peers:
        for i in range(0, 15):
            name = "good_guy_" + str(i)
            ip = "1.1.1." + str(i)
            port = 6660 + i
            strategy = StrategyBenignPeer()
            peer = PeerWithStrategy(output_process_queue, name, strategy, config, {"pigeon_port": port}, ip, self.data_dir)
            peers.append(peer)
            good_peer_ips.append(ip)

        # the bad peers:
        for i in range(15, 20):
            name = "bad_guy_" + str(i)
            ip = "1.1.1." + str(i)
            port = 6660 + i
            strategy = StrategyAttackRandomAndLie()
            peer = PeerWithStrategy(output_process_queue, name, strategy, config, {"pigeon_port": port}, ip, self.data_dir)
            strategy.set_good_peer_list(good_peer_ips)
            strategy.set_module_process(peer)
            peers.append(peer)

        ctrl = Controller(peers, 2, ["1.1.1.0"], ["1.1.1.15"])
        return ctrl

    def get_idtrust_experiment_3(self, output_process_queue, config):
        peers = []
        good_peer_ips = []

        # the good peers:
        for i in range(0, 15):
            name = "good_guy_" + str(i)
            ip = "1.1.1." + str(i)
            port = 6660 + i
            strategy = StrategyBenignPeer()
            peer = PeerWithStrategy(output_process_queue, name, strategy, config, {"pigeon_port": port}, ip, self.data_dir)
            peers.append(peer)
            good_peer_ips.append(ip)

        # the bad peers:
        for i in range(15, 20):
            name = "bad_guy_" + str(i)
            ip = "1.1.1." + str(i)
            port = 6660 + i
            strategy = StrategyAttackRandomAndLie()
            peer = PeerWithStrategy(output_process_queue, name, strategy, config, {"pigeon_port": port}, ip, self.data_dir)
            strategy.set_good_peer_list(good_peer_ips)
            strategy.set_module_process(peer)
            peers.append(peer)

        ctrl = Controller(peers, 2, ["1.1.1.0"], ["1.1.1.15"])
        return ctrl