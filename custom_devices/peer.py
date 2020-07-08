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
                 name="default_device_name",
                 is_good=True):
        Device.__init__(self, ip_address, name, is_good)

        self.port = port
        self.override_p2p = override_p2p

        Trust.__init__(self,
                       output_queue,
                       config,
                       data_dir,
                       pigeon_port=self.port,
                       rename_with_port=True,
                       start_pigeon=False,
                       rename_redis_ip_info=True,
                       rename_sql_db_file=True,
                       override_p2p=self.override_p2p)
