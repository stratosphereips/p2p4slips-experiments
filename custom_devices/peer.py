import multiprocessing
import configparser
from p2ptrust.p2ptrust import Trust
from p2ptrust.testing.experiments.custom_devices.device import Device


class Peer(Trust, multiprocessing.Process, Device):
    """
           Trust(Module,Process)             Device(Object)
       (the trust module)              (a network entity)
                |                        |           |
                |                        |           |
                |                        |           |
                |                        |           + MaliciousDevice(Device)
                |                        |             (a custom device with malicious intentions)
                |                        |
                |                        |
                |                        |
                +------------------------+
                    Peer(Trust,Device)                                   <---- you are here
                    (a network entity with P2P capabilities)
                             |
                             |
                             |
                             |
                             |
                             + MaliciousPeer(Peer)
                               (a peer that can run attacks, but also cheat in the P2P network)

    """

    def __init__(self,
                 output_queue: multiprocessing.Queue,
                 config: configparser.ConfigParser,
                 port: int,
                 override_p2p=False,
                 data_dir="./",
                 ip_address="0.0.0.0",
                 name="default_device_name"):

        multiprocessing.Process.__init__(self)

        self.output_queue = output_queue
        self.config = config
        self.data_dir = data_dir
        self.port = port
        self.ip_address = ip_address
        self.name = name
        self.override_p2p = override_p2p
        self.is_good = True

        super().__init__(output_queue,
                         config,
                         self.data_dir,
                         pigeon_port=self.port,
                         rename_with_port=True,
                         start_pigeon=False,
                         rename_redis_ip_info=True,
                         rename_sql_db_file=True,
                         override_p2p=self.override_p2p)
