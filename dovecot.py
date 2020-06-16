# a communicating interface that replaces all pigeons and just forwards messages directly between peers

# forward slips updates to peers
# listen to messages from all peers
# send messages to other peers
import time
import multiprocessing

# make imports from parent directory possible
import sys
import os
# we need to go all the way up, because modules import slips-wide stuff
from peerwithstrategy import PeerWithStrategy

sys.path.append(os.getcwd() + '/../../..')
from slips.core.database import __database__


class Dovecot(multiprocessing.Process):

    def __init__(self, peers: list):
        super().__init__()

        self.peers = peers
        self.peers_by_name = {}

        # "p2p_gopy" this is where pigeon sends messages to the module core (GoListener is taking care of that)
        # "p2p_data_request" is a channel when Slips asks for network opinion - this will be used to get results out of the network
        # "ip_info_change" this is where slips notifies the module that ip info has been changed. We will push into this channel, not subscribe
        # "p2p_pygo" this is where the core sends messages to the pigeon, these are always forwarded to other nodes (this is what we subscribe to)

        self.pubsub = __database__.r.pubsub()
        for peer in self.peers:
            self.pubsub.subscribe(peer.pygo_channel)
            self.peers_by_name[peer.name] = peer

        outgoing_channel_types = ["p2p_gopy", "p2p_data_request", "ip_info_change"]

    def deactivate_peer(self, peer_name):
        peer = self.peers_by_name[peer_name]
        self.peers.remove(peer)
        self.peers_by_name[peer_name] = None

    def activate_peer(self, peer, peer_name):
        self.peers_by_name[peer_name] = peer
        self.peers.append(peer)

    def run(self):
        try:
            # Main loop function
            while True:
                message = self.pubsub.get_message(timeout=None)

                channel = message["channel"]
                print("Message on channel: ", channel)

                # skip control messages, such as subscribe notifications
                if message['type'] != "message":
                    continue

                data = message['data']
                print("Message contents: ", data)
        except:
            pass

    def send_string_to_peer_name(self, peer_name, send_string):
        if peer_name == "*":
            for single_peer_name in self.peers_by_name.keys():
                self.send_string_to_peer_name(single_peer_name, send_string)
            return
        else:
            peer = self.peers_by_name[peer_name]
            self.send_string_to_peer(peer, send_string)

    def send_string_to_peer(self, peer: PeerWithStrategy, send_string: str):
        channel_name = peer.gopy_channel()
        __database__.publish(channel_name, send_string)

    def forward_message_to_peer(self, source_peer_name, message_data):
        # {"message": "ewogICAgIm........jYKfQ==","recipient": "peer_name_goes_here"}

        # go adds some data to the message:
        # [
        # {
        # "reporter": "abcsakughroiauqrghaui",   // the peer that sent the data
        # "report_time": 154900000,              // time of receiving the data
        # "message": "ewogICAgImtleV90eXBlIjogImlwIiwKICAgICJrZXkiOiAiMS4yLjMuNDAiLAogICAgImV........jYKfQ=="
        # }
        # ]

        data_content = [{"reporter": source_peer_name, "report_time": time.time(), "message": message_data["message"]}]
        self.send_string_to_peer_name(message_data["recipient"], str(data_content))
        pass

    def send_reliability_to_peer(self, local_peer_name, remote_peer_name, peer_ip, reliability, timestamp):
        update_data = {"peerid": remote_peer_name, "ip": peer_ip, "reliability": reliability, "timestamp": timestamp}
        message = "peer_update " + str(update_data)

        self.send_string_to_peer_name(local_peer_name, message)
