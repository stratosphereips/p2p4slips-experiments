import json

from p2ptrust.testing.experiments.ipdb import IPDatabase

threshold = -0.5


def evaluate(observations: dict, ipdb: IPDatabase, rounds, is_good=None):
    # TODO: this doesn't take into consideration the fact that intentions of IP addresses change.
    #  IP address is classified as good/bad by what it says in ipdb right now, not during the experiment.

    if is_good is None:
        is_good = {}
    # print(observations)

    tp = 0  # correctly identified attackers
    tn = 0  # correctly identified benign ips
    fp = 0  # falsely accused benign ips
    fn = 0  # undetected attackers

    if ipdb is not None:
        is_good = {ip_address: ipdb.ips[ip_address].is_good for ip_address in ipdb.ips.keys()}

    for rnd in range(0, rounds):
        try:
            rnd_data = observations[rnd]
        except KeyError:
            rnd_data = observations[str(rnd)]

        if rnd < 10:
            continue

        for observer in rnd_data.keys():
            for observed_ip in rnd_data[observer].keys():
                nscore, nconfidence, score, confidence = rnd_data[observer][observed_ip]
                # print(nscore, nconfidence, score, confidence)
                gt = is_good[observed_ip]

                decision = ((score * confidence) + (nscore * nconfidence)) / 2
                # print(decision)
                if decision < threshold:
                    # we say it is an attacker
                    if gt:
                        fp += 1  # we are wrong
                    else:
                        tp += 1  # we are right
                else:
                    # we say he is benign
                    if gt:
                        tn += 1  # we are right
                    else:
                        fn += 1  # we are wrong

    print("STATS: ", tp, tn, fp, fn)
    success = tp + tn
    all = tp + tn + fp + fn
    accuracy = success / all
    print("ACCURACY: ", accuracy)


if __name__ == '__main__':
    exp_dir = "/home/dita/p2ptrust-link/testing/experiments/experiment_data/experiments-1594815406.4306164/"
    exp_suffix = "_keep_malicious_device_unblocked"
    is_good = {"1.1.1.10": False}

    for i in range(0, 10):
        # the following is correct, but overly complex, as I only ever check 1.1.1.10 :D
        # is_good = {"1.1.1." + str(10 - j): True if i < 10 - j else False for j in range(1, 11)}
        data_file = exp_dir + str(i) + exp_suffix + "/round_results.txt"
        print("Number of malicious peers: " + str(i) + "/10")
        with open(data_file, "r") as f:
            data = json.load(f)
            evaluate(data, None, 20, is_good)

