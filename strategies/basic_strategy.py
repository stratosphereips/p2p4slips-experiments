# a simple strategy
from sampler import Attack
from utils import NetworkUpdate


class Strategy:
    def __init__(self):
        self.override_handle_update = False
        self.override_handle_data_request = False
        self.is_good = True

    def on_round_start(self, round_no: int):
        raise NotImplementedError

    def choose_round_behavior(self, round_no: int, peer_ids: list):
        raise NotImplementedError

    def on_round_end(self, round_no: int):
        raise NotImplementedError

    def handle_update(self, ip_address: str):
        raise NotImplementedError

    def handle_data_request(self, message_data: str):
        raise NotImplementedError
