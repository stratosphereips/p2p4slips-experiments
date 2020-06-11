# extends peer, calls actions from strategies

# make imports from parent directory possible
import sys
import os
# we need to go all the way up, because modules import slips-wide stuff
sys.path.append(os.getcwd() + '/../../..')

# this imports files from the p2ptrust slips module
from modules.p2ptrust.trustdb import TrustDB
from modules.p2ptrust.reputation_model import ReputationModel
from modules.p2ptrust.printer import Printer

class PeerWithStrategy:

    def __init__(self, printer: Printer, peer_identifier: str, strategy):
        self.printer = printer
        self.name = peer_identifier
        self.strategy = strategy
        self.db_file = os.path.abspath("databases/" + peer_identifier + ".sql")
        print(os.path.abspath(self.db_file))
        self.trustDB = TrustDB(self.db_file, self.printer, drop_tables_on_startup=True)
        self.reputationModel = ReputationModel(self.printer, self.trustDB, None)

    def make_choice(self, round, peer_names):
        return self.strategy(round, peer_names)


