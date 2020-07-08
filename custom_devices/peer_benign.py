import multiprocessing
import configparser
from p2ptrust.testing.experiments.custom_devices.peer import Peer


class PeerBenign(Peer):

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
                         override_p2p=False,
                         name=name)

