import configparser
import os

from p2ptrust.testing.experiments.controller import Controller
from p2ptrust.testing.experiments.custom_devices.device_benign import DeviceBenign
from p2ptrust.testing.experiments.custom_devices.device_malicious import DeviceMalicious
from p2ptrust.testing.experiments.custom_devices.peer_benign import PeerBenign
from p2ptrust.testing.experiments.custom_devices.peer_liar_everyone_is_good import PeerLiarEveryoneIsGood
from p2ptrust.utils.utils import read_configuration


class Setups:
    def __init__(self, data_dir):
        self.setups = [self.get_test_experiment]
        self.data_dir = data_dir

    def get_experiment(self, id, output_process_queue, config):
        return self.setups[id](id, output_process_queue, config)

    def get_test_experiment(self, identifier: int, output_process_queue, config: configparser.ConfigParser):
        data_dir = self.data_dir + str(identifier) + "/"
        os.mkdir(data_dir)
        p0 = PeerBenign(output_queue=output_process_queue,
                        config=config,
                        data_dir=data_dir,
                        port=6660,
                        ip_address="1.1.1.0",
                        name="0_peer_benign")
        p0.start()

        # later, this device will be malicious
        p1 = DeviceMalicious(ip_address="1.1.1.1", name="1_device_malicious", port=6661)

        p2 = PeerLiarEveryoneIsGood(output_process_queue,
                                    config,
                                    pigeon_port=6662,
                                    rename_with_port=True,
                                    start_pigeon=False,
                                    override_p2p=True,
                                    rename_redis_ip_info=True,
                                    rename_sql_db_file=True,
                                    data_dir=data_dir,
                                    ip_address="1.1.1.2",
                                    name="2_peer_malicious")
        p2.start()

        peers = [p0, p1, p2]

        ctrl = Controller(peers, 3, ["1.1.1.0"], ["1.1.1.1"], data_dir)
        return ctrl
