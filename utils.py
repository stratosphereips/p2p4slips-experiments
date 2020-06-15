# make imports from parent directory possible
import sys
import os
# we need to go all the way up, because modules import slips-wide stuff
import json

sys.path.append(os.getcwd() + '/../../..')
from slips.core.database import __database__


def update_slips_scores(storage_name, channel_name, ip, score, confidence):
    data = {"score": score, "confidence": confidence}
    __database__.r.hset(storage_name, ip, json.dumps(data))
    __database__.r.publish(channel_name, ip)
