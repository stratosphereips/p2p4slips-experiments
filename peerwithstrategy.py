# extends peer, calls actions from strategies
from configparser import ConfigParser

# make imports from parent directory possible
import sys
import os

# we need to go all the way up, because modules import slips-wide stuff
sys.path.append(os.getcwd() + '/../../..')

# this imports files from the p2ptrust slips module
from modules.p2ptrust.trustdb import TrustDB
from modules.p2ptrust.p2ptrust import Trust
from modules.p2ptrust.reputation_model import ReputationModel
from modules.p2ptrust.printer import Printer

from strategies.basic_strategy import Strategy


class PeerWithStrategy(Trust):

    def __init__(self, output_queue, peer_identifier: str, strategy: Strategy, config: ConfigParser,
                 trust_params: dict, ipaddress: str):
        self.parent = super()
        self.parent.__init__(output_queue,
                         config,
                         pigeon_port=trust_params["pigeon_port"],
                         rename_with_port=True,
                         slips_update_channel="ip_info_change",
                         p2p_data_request_channel="p2p_data_request",
                         gopy_channel="p2p_gopy",
                         pygo_channel="p2p_pygo",
                         pigeon_logfile="",
                         start_pigeon=False)

        self.name = peer_identifier
        self.strategy = strategy
        self.ipaddress = ipaddress
        self.port = trust_params["pigeon_port"]

    def on_round_start(self, round: int):
        self.strategy.on_round_start(round)

    def make_choice(self, round, peer_names):
        return self.strategy.choose_round_behavior(round, peer_names)

    def on_round_end(self, round: int):
        self.strategy.on_round_end(round)

    def handle_update(self, ip_address: str) -> None:
        print("handle_update was called")
        pass

    def handle_data_request(self, message_data: str) -> None:
        print("handle_update was called")
        pass