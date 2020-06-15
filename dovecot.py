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
sys.path.append(os.getcwd() + '/../../..')
from slips.core.database import __database__


class Dovecot(multiprocessing.Process):

    def __init__(self, peer_ports: dict):
        super().__init__()

        self.peer_ports = peer_ports
        #self.peer_ports = {"p1": 6666}
        self.peer_names = {}

        # "p2p_gopy" this is where pigeon sends messages to the module core (GoListener is taking care of that)
        # "p2p_data_request" is a channel when Slips asks for network opinion - this will be used to get results out of the network
        # "ip_info_change" this is where slips notifies the module that ip info has been changed. We will push into this channel, not subscribe
        # "p2p_pygo" this is where the core sends messages to the pigeon, these are always forwarded to other nodes (this is what we subscribe to)

        self.pubsub = __database__.r.pubsub()
        for peer_name, peer_port in self.peer_ports.items():
            self.peer_names[peer_port] = peer_name
            self.pubsub.subscribe("p2p_pygo" + str(peer_port))

        outgoing_channel_types = ["p2p_gopy", "p2p_data_request", "ip_info_change"]

    def deactivate_peer(self, peer_name):
        port = self.peer_ports[peer_name]
        self.peer_names[port] = None
        self.peer_ports[peer_name] = None

    def activate_peer(self, peer_name, peer_port):
        self.peer_names[peer_port] = peer_name
        self.peer_ports[peer_name] = peer_port

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

    def send_string_to_channel(self, peer_name, send_string):
        if peer_name == "*":
            for single_peer_name in self.peer_names.values():
                self.send_string_to_channel(single_peer_name, send_string)
            return
        peer_port = self.peer_ports[peer_name]
        channel_name = "p2p_gopy" + str(peer_port)
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
        self.send_string_to_channel(message_data["recipient"], "p2p_gopy", str(data_content))
        pass

    def send_reliability_to_peer(self, local_peer_name, remote_peer_name, peer_ip, reliability, timestamp):
        update_data = {"peerid": remote_peer_name, "ip": peer_ip, "reliability": reliability, "timestamp": timestamp}
        message = "peer_update " + str(update_data)

        self.send_string_to_channel(local_peer_name, message)
