import multiprocessing
import configparser
from p2ptrust.p2ptrust import Trust
from p2ptrust.testing.experiments.custom_devices.device import Device
from p2ptrust.testing.experiments.sampler import Attack
from p2ptrust.testing.experiments.utils import NetworkUpdate


class PeerLiarEveryoneIsGood(Trust, multiprocessing.Process, Device):
    # Name: short name of the module. Do not use spaces
    name = 'p2ptrust'
    description = 'Enables sharing detection data with other Slips instances'
    authors = ['Dita']

    def __init__(self,
                 output_queue: multiprocessing.Queue,
                 config: configparser.ConfigParser,
                 data_dir: str,
                 pigeon_port=6668,
                 start_pigeon=False,
                 rename_with_port=False,
                 slips_update_channel="ip_info_change",
                 p2p_data_request_channel="p2p_data_request",
                 gopy_channel="p2p_gopy",
                 pygo_channel="p2p_pygo",
                 rename_redis_ip_info=False,
                 rename_sql_db_file=False,
                 ip_address="0.0.0.0",
                 name="default_device_name",
                 override_p2p=False):
        multiprocessing.Process.__init__(self)

        self.output_queue = output_queue
        self.config = config
        self.data_dir = data_dir
        self.port = pigeon_port
        self.start_pigeon = start_pigeon
        self.rename_with_port = rename_with_port
        self.slips_update_channel_raw = slips_update_channel
        self.p2p_data_request_channel_raw = p2p_data_request_channel
        self.gopy_channel_raw = gopy_channel
        self.pygo_channel_raw = pygo_channel
        self.rename_redis_ip_info = rename_redis_ip_info
        self.rename_sql_db_file = rename_sql_db_file
        self.ip_address = ip_address
        self.name = name
        self.override_p2p = override_p2p

        super().__init__(output_queue,
                         config,
                         self.data_dir,
                         pigeon_port=self.port,
                         rename_with_port=self.rename_with_port,
                         slips_update_channel=self.slips_update_channel_raw,
                         p2p_data_request_channel=self.p2p_data_request_channel_raw,
                         gopy_channel=self.gopy_channel_raw,
                         pygo_channel=self.pygo_channel_raw,
                         start_pigeon=False,
                         rename_redis_ip_info=self.rename_redis_ip_info,
                         rename_sql_db_file=self.rename_sql_db_file,
                         override_p2p=self.override_p2p)

        self.is_good = False

    def handle_data_request(self, params):
        pass

    def handle_update(self, ip_address: str) -> None:
        pass

    def respond_to_message_request(self, key, reporter):
        print("message request in parent was called")
        # time.sleep(100)
        self.go_listener_process.send_evaluation_to_go(key, 1, 1, reporter)
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
