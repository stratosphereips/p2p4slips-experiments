import multiprocessing
import configparser

from p2ptrust.testing.experiments.custom_devices.peer import Peer


class PeerLiarTargetIsBad(Peer):
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
                    Peer(Trust,Device)
                    (a network entity with P2P capabilities)
                             |
                             |
                             |
                             |
                             |
     you are here ---->      + MaliciousPeer(Peer)
                               (a peer that can run attacks, but also cheat in the P2P network)

    """

    def __init__(self,
                 output_queue: multiprocessing.Queue,
                 config: configparser.ConfigParser,
                 data_dir: str,
                 port: int,
                 ip_address: str,
                 name: str,
                 target_ips: list = None):

        self.target_ips = target_ips

        Peer.__init__(self,
                      output_queue,
                      config,
                      port=port,
                      ip_address=ip_address,
                      data_dir=data_dir,
                      override_p2p=True,
                      name=name,
                      is_good=False)

    def handle_data_request(self, params):
        pass

    def handle_update(self, ip_address: str) -> None:
        pass

    def respond_to_message_request(self, key, reporter):
        # time.sleep(100)
        if key in self.target_ips:
            print("sending bad report about victim: " + key)
            self.go_listener_process.send_evaluation_to_go(key, -1, 1, reporter)
        else:
            print("sending good report about someone else: " + key)
            self.go_listener_process.send_evaluation_to_go(key, 1, 1, reporter)

    def process_message_report(self, reporter: str, report_time: int, data: dict):
        print("message report in parent was called")
        pass
