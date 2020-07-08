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
                         override_p2p=False,
                         name=name)

