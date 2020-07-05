class Device:
    def __init__(self, ip_address="0.0.0.0"):
        self.ip_address = ip_address

    def on_round_start(self, round_no: int):
        raise NotImplementedError

    def choose_round_behavior(self, round_no: int, peer_ids: list):
        raise NotImplementedError

    def on_round_end(self, round_no: int):
        raise NotImplementedError
