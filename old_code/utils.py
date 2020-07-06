# make imports from parent directory possible
import enum
import sys
import os
# we need to go all the way up, because modules import slips-wide stuff
import json

sys.path.append(os.getcwd() + '/../../..')
from slips.core.database import __database__

class NetworkUpdate(enum.Enum):
    Stay = 0
    JoinWithNewIp = 1
    JoinWithSameIp = 2
    ChangeIp = 3
    Leave = 4


def update_slips_scores(storage_name, channel_name, ip, score, confidence):
    data = {"score": score, "confidence": confidence}
    __database__.r.hset(storage_name, ip, json.dumps(data))
    __database__.r.publish(channel_name, ip)


def publish_str_to_channel(channel_name, message):
    print("XXXXXXXXXXXXXXXXXXXXXXXXX Sending message to channel: " + channel_name)
    __database__.r.publish(channel_name, message)


def get_network_score_confidence(storage_name, ip):
    data = __database__.r.hget(storage_name, ip)
    parsed_data = json.loads(data)
    try:
        net_opinion_data = parsed_data["p2p4slips"]
        score = net_opinion_data["score"]
        confidence = net_opinion_data["confidence"]
    except KeyError:
        return 0, 0
    return score, confidence