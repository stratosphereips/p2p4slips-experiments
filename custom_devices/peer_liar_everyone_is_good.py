import multiprocessing
import configparser
import platform
import signal
import subprocess
import time

from p2ptrust.testing.experiments.custom_devices.device import Device
from p2ptrust.testing.experiments.old_code.sampler import Attack
from p2ptrust.testing.experiments.old_code.utils import NetworkUpdate
from slips.core.database import __database__
from slips.common.abstracts import Module

import p2ptrust.trust.trustdb as trustdb
from p2ptrust.utils.printer import Printer
import p2ptrust.trust.trust_model as reputation_model
import p2ptrust.utils.go_listener as go_listener
import p2ptrust.utils.utils as utils


def validate_slips_data(message_data: str) -> (str, int):
    """
    Check that message received from slips channel has correct format: ip, timeout

    The message should contain an IP address (string), followed by a space and an integer timeout. If the message is
    correct, the two values are returned as a tuple (str, int). If not, (None, None) is returned.
    :param message_data: data from slips request channel
    :return: parsed values or None tuple
    """

    try:
        ip_address, time_since_cached = message_data.split(" ", 1)
        time_since_cached = int(time_since_cached)

        if not utils.validate_ip_address(ip_address):
            return None, None

        return ip_address, time_since_cached

    except ValueError:
        # message has wrong format
        return None, None


class PeerLiarEveryoneIsGood(Module, multiprocessing.Process, Device):
    # Name: short name of the module. Do not use spaces
    name = 'p2ptrust'
    description = 'Enables sharing detection data with other Slips instances'
    authors = ['Dita']

    def __init__(self,
                 output_queue: multiprocessing.Queue,
                 config: configparser.ConfigParser,
                 pigeon_port=6668,
                 rename_with_port=False,
                 slips_update_channel="ip_info_change",
                 p2p_data_request_channel="p2p_data_request",
                 gopy_channel="p2p_gopy",
                 pygo_channel="p2p_pygo",
                 start_pigeon=True,
                 pigeon_logfile="pigeon_logs",
                 rename_redis_ip_info=False,
                 rename_sql_db_file=False,
                 override_p2p=False,
                 data_dir="./",
                 ip_address="0.0.0.0",
                 name="default_device_name"):
        multiprocessing.Process.__init__(self)

        self.ip_address = ip_address
        self.name = name
        self.is_good = False
        self.output_queue = output_queue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        # To which channels do you want to subscribe? When a message arrives on the channel the module will wakeup
        # The options change, so the last list is on the slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added

        self.port = pigeon_port
        self.rename_with_port = rename_with_port
        self.slips_update_channel_raw = slips_update_channel
        self.p2p_data_request_channel_raw = p2p_data_request_channel
        self.gopy_channel_raw = gopy_channel
        self.pygo_channel_raw = pygo_channel
        self.pigeon_logfile_raw = pigeon_logfile
        self.start_pigeon = start_pigeon
        self.override_p2p = override_p2p

        if self.rename_with_port:
            str_port = str(self.port)
        else:
            str_port = ""

        self.printer = Printer(output_queue, self.name + str_port)

        self.slips_update_channel = self.slips_update_channel_raw + str_port
        self.p2p_data_request_channel = self.p2p_data_request_channel_raw + str_port
        self.gopy_channel = self.gopy_channel_raw + str_port
        self.pygo_channel = self.pygo_channel_raw + str_port
        self.pigeon_logfile = data_dir + self.pigeon_logfile_raw + str_port

        self.storage_name = "IPsInfo"
        if rename_redis_ip_info:
            self.storage_name += str(self.port)

        # Set the timeout based on the platform. This is because the pyredis lib does not have officially recognized the
        # timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            # linux
            self.timeout = -1
        else:
            # ??
            self.timeout = None

        __database__.start(self.config)
        self.pubsub = __database__.r.pubsub()
        self.pubsub.subscribe(self.slips_update_channel)
        self.pubsub.subscribe(self.p2p_data_request_channel)

        # TODO: do not drop tables on startup
        sql_db_name = data_dir + "trustdb.db"
        if rename_sql_db_file:
            sql_db_name += str(pigeon_port)
        self.trust_db = trustdb.TrustDB(sql_db_name, self.printer, drop_tables_on_startup=True)
        self.reputation_model = reputation_model.TrustModel(self.printer, self.trust_db, self.config)

        self.go_listener_process = go_listener.GoListener(self.printer, self.trust_db, self.config, self.storage_name, self,
                                                          gopy_channel=self.gopy_channel, pygo_channel=self.pygo_channel)
        self.go_listener_process.start()

        if self.start_pigeon:
            outfile = open(self.pigeon_logfile, "+w")
            executable = ["/home/dita/ownCloud/m4.semestr/go/src/github.com/stratosphereips/p2p4slips/p2p4slips"]
            port_param = ["-port", str(self.port)]
            keyfile_param = ["-key-file", "fofobarbarkeys"]
            rename_with_port_param = ["-rename-with-port", str(self.rename_with_port).lower()]
            pygo_channel_param = ["-redis-channel-pygo", self.pygo_channel_raw]
            gopy_channel_param = ["-redis-channel-gopy", self.gopy_channel_raw]
            executable.extend(port_param)
            executable.extend(keyfile_param)
            executable.extend(rename_with_port_param)
            executable.extend(pygo_channel_param)
            executable.extend(gopy_channel_param)

            self.pigeon = subprocess.Popen(executable)

    def print(self, text: str, verbose: int = 1, debug: int = 0) -> None:
        self.printer.print(text, verbose, debug)

    def run(self):
        try:
            # Main loop function
            while True:
                message = self.pubsub.get_message(timeout=None)
                # skip control messages, such as subscribe notifications
                if message['type'] != "message":
                    continue

                data = message['data']

                # listen to slips kill signal and quit
                if data == 'stop_process':
                    self.print("Received stop signal from slips, stopping")
                    self.trust_db.__del__()
                    self.go_listener_process.kill()
                    if self.start_pigeon:
                        self.pigeon.send_signal(signal.SIGINT)
                    return True

                if message["channel"] == self.slips_update_channel:
                    self.print("IP info was updated in slips for ip: " + data)
                    self.handle_update(message["data"])
                    continue

                if message["channel"] == self.p2p_data_request_channel:
                    self.handle_data_request(message["data"])
                    continue

        except KeyboardInterrupt:
            return True
        # except Exception as inst:
        #     self.print('Problem on the run()', 0, 1)
        #     self.print(str(type(inst)), 0, 1)
        #     self.print(str(inst.args), 0, 1)
        #     self.print(str(inst), 0, 1)
        #     return True

    def handle_update(self, ip_address: str) -> None:
        """
        Handle IP scores changing in Slips received from the ip_info_change channel

        This method checks if new score differs from opinion known to the network, and if so, it means that it is worth
        sharing and it will be shared. Additionally, if the score is serious, the node will be blamed
        :param ip_address: The IP address sent through the ip_info_change channel (if it is not valid IP, it returns)
        """

        # abort if the IP is not valid
        if not utils.validate_ip_address(ip_address):
            self.print("IP validation failed")
            return

        print(self.storage_name)
        score, confidence = utils.get_ip_info_from_slips(ip_address, self.storage_name)
        if score is None:
            self.print("IP doesn't have any score/confidence values in DB")
            return

        # insert data from slips to database
        # TODO: remove debug timestamps
        self.trust_db.insert_slips_score(ip_address, score, confidence)

        # TODO: discuss - only share score if confidence is high enough?
        # compare slips data with data in go
        data_already_reported = True
        try:
            cached_opinion = self.trust_db.get_cached_network_opinion("ip", ip_address)
            cached_score, cached_confidence, network_score, timestamp = cached_opinion
            if cached_score is None:
                data_already_reported = False
            elif abs(score - cached_score) < 0.1:
                data_already_reported = False
        except KeyError:
            data_already_reported = False
        except IndexError:
            # data saved in local db have wrong structure, this is an invalid state
            return

        # TODO: in the future, be smarter and share only when needed. For now, we will always share
        # if not data_already_reported:
        #     send_evaluation_to_go(ip_address, score, confidence, "*")
        utils.send_evaluation_to_go(ip_address, score, confidence, "*", self.pygo_channel)

        # TODO: discuss - based on what criteria should we start blaming?
        if score > 0.8 and confidence > 0.6:
            utils.send_blame_to_go(ip_address, score, confidence, self.pygo_channel)

    def handle_data_request(self, params):
        pass

    def respond_to_message_request(self, key, reporter):
        print("message request in parent was called")
        pass

    def process_message_report(self, reporter: str, report_time: int, data: dict):
        print("message report in parent was called")
        pass

    def on_round_start(self, round_no: int):
        if round_no == 0:
            return NetworkUpdate.JoinWithSameIp, None
        return None, None

    def choose_round_behavior(self, round_no: int, peer_ips: list):
        attack_plan = dict.fromkeys(peer_ips, Attack.Benign)
        return attack_plan

    def on_round_end(self, round_no: int):
        pass