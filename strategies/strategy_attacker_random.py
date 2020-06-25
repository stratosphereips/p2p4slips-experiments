from sampler import Attack
from strategies.basic_strategy import Strategy
from utils import NetworkUpdate


class StrategyAttackRandomAndLie(Strategy):

    def __init__(self):
        super().__init__()
        self.override_handle_update = True
        self.override_handle_data_request = True
        self.is_good = False
        self.do_p2p = True
        self.module_process = None
        self.go_listener = None
        self.pygo_channel = ""
        self.storage_name = ""
        self.good_peer_list = []
    
    def set_module_process(self, module_process):
        self.module_process = module_process
        print("Type in set", type(module_process))

        self.go_listener = module_process.go_listener_process
        self.pygo_channel = module_process.pygo_channel
        self.storage_name = module_process.storage_name

    def set_good_peer_list(self, victim_list):
        self.good_peer_list = victim_list

    def on_round_start(self, round_no: int):
        if round_no == 0:
            return NetworkUpdate.JoinWithSameIp, None
        return None, None

    def choose_round_behavior(self, round_no: int, peer_ips: list):
        attack_plan = dict.fromkeys(peer_ips, Attack.GeneralAttack)
        return attack_plan

    def on_round_end(self, round_no: int):
        pass

    def handle_update(self, ip_address: str):
        print("I am an attacker, I don't check score updates")

    def handle_data_request(self, message_data: str):
        print("I am an attacker, I don't respond to queries")

    def respond_to_message_request(self, key, reporter):
        # always report good peers are bad, bad peers are good
        if key in self.good_peer_list:
            score = -1
        else:
            score = 1

        # always be very sure about the decisions
        confidence = 1

        self.go_listener.send_evaluation_to_go(key, score, confidence, reporter, self.pygo_channel)

    def process_message_report(self, reporter: str, report_time: int, data: dict):
        pass
