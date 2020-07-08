from p2ptrust.testing.experiments.sampler import Attack
from p2ptrust.testing.experiments.utils import NetworkUpdate


class Device:
    """
    Device is the basic network entity the experiment interface works with. Device has an IP address, a name and a
    boolean value marking it's intentions - this one is important for evaluation.

    The device must respond to three functions:
    1) on_round_start() - this is called in each round of the experiment, and the device can choose to join the network,
                          leave it or change IP addresses
    2) choose_round_behavior() -  in each round, the device will decide to behave well, or to send malicious data (an
                                  attack.
    3) on_round_end() - similar as on_round_start, except it is not implemented yet :D

    This object can be used as a Template for other, even malicious devices, by overriding the functions. Usually, only
    the behavior function needs to be customized.

    Even Peers are specific instance of a Device, as they have the same behavior, but also have a trust module running
    in the background.

    The inheritance in this project has the following structure:

       Trust(Module,Process)             Device(Object)        <---- you are here
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
                             + MaliciousPeer(Peer)
                               (a peer that can run attacks, but also cheat in the P2P network)

    """
    def __init__(self, ip_address="0.0.0.0", name="", is_good=True):
        self.ip_address = ip_address
        self.name = name
        self.is_good = is_good

    def on_round_start(self, round_no: int):
        if round_no == 0:
            return NetworkUpdate.JoinWithSameIp, None
        return None, None

    def choose_round_behavior(self, round_no: int, peer_ips: list):
        attack_plan = dict.fromkeys(peer_ips, Attack.Benign)
        return attack_plan

    def on_round_end(self, round_no: int):
        pass
