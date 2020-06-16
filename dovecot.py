# a communicating interface that replaces all pigeons and just forwards messages directly between peers

# forward slips updates to peers
# listen to messages from all peers
# send messages to other peers
import json
import time
import multiprocessing

# make imports from parent directory possible
import sys
import os
# we need to go all the way up, because modules import slips-wide stuff
from ipdb import IPDatabase
from peerwithstrategy import PeerWithStrategy

sys.path.append(os.getcwd() + '/../../..')
from slips.core.database import __database__


class Dovecot(multiprocessing.Process):

    def __init__(self, ipdb: IPDatabase):
        super().__init__()

        self.ipdb = ipdb

        # "p2p_gopy" this is where pigeon sends messages to the module core (GoListener is taking care of that)
        # "p2p_data_request" is a channel when Slips asks for network opinion - this will be used to get results out of the network
        # "ip_info_change" this is where slips notifies the module that ip info has been changed. We will push into this channel, not subscribe
        # "p2p_pygo" this is where the core sends messages to the pigeon, these are always forwarded to other nodes (this is what we subscribe to)

        self.pubsub = __database__.r.pubsub()
        for peer in self.ipdb.peers:
            self.pubsub.subscribe(peer.pygo_channel)

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

                sender = self.get_sender_from_channel(channel)
                dict_data = json.loads(data)
                self.forward_message_to_peer(sender.name, dict_data)
                print("Message contents: ", data)
        except:
            pass

    def send_string_to_peer_name(self, source_peer_name, peer_name, send_string):
        if peer_name == "*":
            for single_peer_name in self.ipdb.names.keys():
                self.send_string_to_peer_name(source_peer_name, single_peer_name, send_string)
            return
        if peer_name == source_peer_name:
            return

        peer = self.ipdb.names[peer_name]
        self.send_string_to_peer(peer, send_string)

    def send_string_to_peer(self, peer: PeerWithStrategy, send_string: str):
        if not peer.active:
            return
        channel_name = peer.gopy_channel
        __database__.publish(channel_name, send_string)

    def forward_message_to_peer(self, source_peer_name, message_data: dict):
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
        message_str = "go_data " + json.dumps(data_content)
        self.send_string_to_peer_name(source_peer_name, message_data["recipient"], message_str)
        pass

    def peer_data_update(self, peer: PeerWithStrategy):
        update_data = {"peerid": peer.name, "reliability": 1, "timestamp": time.time(), "ip": peer.ipaddress}
        message = "peer_update " + json.dumps(update_data)

        self.send_string_to_peer_name(peer.name, "*", message)

    def get_sender_from_channel(self, channel):
        # read port from channel name and return the peer that owns this port
        for i, c in enumerate(channel):
            if not c.isdigit():
                continue
            port_str = channel[i:]
            try:
                port = int(port_str)
                peer = self.ipdb.ports[port]
                return peer
            except:
                continue
        print("Couldn't find peer running on channel " + channel)

