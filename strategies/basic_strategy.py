# a simple strategy
from sampler import Attack

class Strategy:
    def __init__(self):
        self.override_handle_update = False
        self.override_handle_p2p_data_request = False

    def on_round_start(self, round_no: int):
        raise NotImplementedError

    def choose_round_behavior(self, round_no: int, peer_ids: list):
        raise NotImplementedError

    def on_round_end(self, round_no: int):
        raise NotImplementedError
