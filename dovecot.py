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
import redis

from peerwithstrategy import PeerWithStrategy


class Dovecot(multiprocessing.Process):

    def __init__(self, portlist: dict, pygo_channel: str, gopy_channel: str):
        super().__init__()

        # "p2p_gopy" this is where pigeon sends messages to the module core (GoListener is taking care of that)
        # "p2p_data_request" is a channel when Slips asks for network opinion - this will be used to get results out of the network
        # "ip_info_change" this is where slips notifies the module that ip info has been changed. We will push into this channel, not subscribe
        # "p2p_pygo" this is where the core sends messages to the pigeon, these are always forwarded to other nodes (this is what we subscribe to)

        self.r = redis.StrictRedis(host='localhost', port=6379, db=0, charset="utf-8", decode_responses=True)
        self.pubsub = self.r.pubsub()

        self.peer_names = {}  # keys are peerids, values are the ports
        self.peer_ports = {}  # keys are ports, values are names
        self.pygo_channel = pygo_channel
        self.gopy_channel = gopy_channel
        for peer_port, peer_name in portlist.items():
            self.peer_ports[peer_port] = peer_name
            self.peer_names[peer_name] = peer_port
            self.pubsub.subscribe(self.pygo_channel + str(peer_port))
        self.recently_updated_peers = []

        print(self.peer_ports)

    def run(self):
        while True:
            message = self.pubsub.get_message(timeout=None)

            channel = message["channel"]
            print("Message on channel: ", channel)

            # skip control messages, such as subscribe notifications
            if message['type'] != "message":
                continue

            data = message['data']

            sender_name = self.get_sender_name_from_channel(channel)
            dict_data = json.loads(data)
            self.forward_message_to_peer(sender_name, dict_data)
            print("Message contents: ", data)

    def send_string_to_peer_name(self, source_peer_name, peer_name, send_string):
        if peer_name == "*":
            for single_peer_name in self.peer_names.keys():
                self.send_string_to_peer_name(source_peer_name, single_peer_name, send_string)
            return
        if peer_name == source_peer_name:
            return

        port = self.peer_names[peer_name]
        self.send_string_to_port(port, send_string)

    def send_string_to_port(self, port: int, send_string: str):
        # TODO there is something very wrong here. The peers are never active, even though I set them to be active.
        #  The object memory locations didn't change, which leads me to think there is a thread synchronization
        #  thing going on which makes my peers not updated, and therefore inactive
        # if not peer.active:
        #     return
        channel_name = self.gopy_channel + str(port)
        print("XXXXXXXXXXXXXXXXXXXXXXXXX Requesting message to channel: " + channel_name)
        self.publish_str_to_channel(channel_name, send_string)

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

        data_content = {"reporter": source_peer_name, "report_time": time.time(), "message": message_data["message"]}
        data_message = {"message_type": "go_data", "message_contents": data_content}
        message_str = json.dumps(data_message)
        self.send_string_to_peer_name(source_peer_name, message_data["recipient"], message_str)
        pass

    def peer_data_update(self, peer: PeerWithStrategy):
        self.recently_updated_peers.append(peer)

    def get_sender_name_from_channel(self, channel):
        # read port from channel name and return the peer that owns this port
        for i, c in enumerate(channel):
            if not c.isdigit():
                continue
            port_str = channel[i:]
            try:
                port = int(port_str)
                peer = self.peer_ports[port]
                return peer
            except:
                continue
        print("Couldn't find peer running on channel " + channel)

    def notify_at_round_start(self):
        for peer in self.recently_updated_peers:
            update_data = {"peerid": peer.name, "reliability": 1, "timestamp": time.time(), "ip": peer.ipaddress}
            update_message = {"message_type": "peer_update", "message_contents": update_data}
            message = json.dumps(update_message)

            self.send_string_to_peer_name(peer.name, "*", message)

        self.recently_updated_peers = []

    def publish_str_to_channel(self, channel_name, message):
        self.r.publish(channel_name, message)
