from sampler import Attack
from strategies.basic_strategy import Strategy
from utils import NetworkUpdate


class PeerLiarEveryoneIsGood(Strategy):

    def __init__(self):
        super().__init__()
        self.override_handle_update = True
        self.override_handle_data_request = True
        self.is_good = False
        self.do_p2p = True
        # prepare variables
        self.module_process = None
        self.go_listener = "hello"
        self.pygo_channel = ""
        self.storage_name = ""
        self.good_peer_list = []
        print("STARTING LIAR PEER")

    def set_module_process(self, module_process):
        self.module_process = module_process
        print("setting go listener")

        self.go_listener = module_process.go_listener_process
        self.pygo_channel = module_process.pygo_channel
        self.storage_name = module_process.storage_name
        print(self.go_listener)

    def set_good_peer_list(self, victim_list):
        self.good_peer_list = victim_list

    def on_round_start(self, round_no: int):
        if round_no == 0:
            return NetworkUpdate.JoinWithSameIp, None
        return None, None

    def choose_round_behavior(self, round_no: int, peer_ips: list):
        attack_plan = dict.fromkeys(peer_ips, Attack.Benign)
        return attack_plan

    def on_round_end(self, round_no: int):
        pass

    def handle_update(self, ip_address: str):
        pass

    def handle_data_request(self, message_data: str):
        pass

    def respond_to_message_request(self, key, reporter):
        print("ALTERING REPORT DATA")
        self.go_listener.send_evaluation_to_go(key, 1, 1, reporter, self.pygo_channel)

    def process_message_report(self, reporter: str, report_time: int, data: dict):
        pass
