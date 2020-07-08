import multiprocessing
import configparser
from p2ptrust.p2ptrust import Trust
from p2ptrust.testing.experiments.custom_devices.device import Device
from p2ptrust.testing.experiments.custom_devices.peer import Peer
from p2ptrust.testing.experiments.sampler import Attack
from p2ptrust.testing.experiments.utils import NetworkUpdate


class PeerLiarEveryoneIsGood(Peer):

    def __init__(self,
                 output_queue: multiprocessing.Queue,
                 config: configparser.ConfigParser,
                 data_dir: str,
                 port: int,
                 ip_address: str,
                 name: str):

        super().__init__(output_queue,
                         config,
                         port=port,
                         ip_address=ip_address,
                         data_dir=data_dir,
                         rename_with_port=True,
                         start_pigeon=False,
                         rename_redis_ip_info=True,
                         rename_sql_db_file=True,
                         override_p2p=True,
                         name=name)

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
