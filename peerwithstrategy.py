# extends peer, calls actions from strategies

class PeerWithStrategy:

    def __init__(self, strategy, number_of_peers):
        self.strategy = strategy
        self.number_of_peers = number_of_peers

    def make_choice(self, round):
        return self.strategy(round, self.number_of_peers)
