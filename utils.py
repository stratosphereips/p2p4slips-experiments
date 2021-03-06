# make imports from parent directory possible
import enum
import sys
import os
# we need to go all the way up, because modules import slips-wide stuff
import json
import time
from multiprocessing import Queue

from outputProcess import OutputProcess
from p2ptrust.testing.test_p2p import get_default_config

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


def prepare_experiments_dir(base_dir, exp_name="", timestamp=""):
    if timestamp == "":
        timestamp = str(time.time())
    base_dir = base_dir + timestamp + exp_name + "/"

    if not os.path.exists(base_dir):
        os.mkdir(base_dir)

    return base_dir


def init_experiment(base_dir, exp_id, exp_suffix=""):
    config = get_default_config()
    output_process_queue = Queue()
    output_process_thread = OutputProcess(output_process_queue, 1, 1, config)
    output_process_thread.start()

    # Start the DB
    __database__.start(config)
    __database__.setOutputQueue(output_process_queue)

    exp_dir = base_dir + str(exp_id) + exp_suffix + "/"

    if not os.path.exists(exp_dir):
        os.mkdir(exp_dir)

    return config, output_process_queue, output_process_thread, exp_dir
