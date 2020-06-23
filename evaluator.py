from ipdb import IPDatabase
threshold = -0.5


def evaluate(observations: dict, ipdb: IPDatabase, rounds):
    # TODO: this doesn't take into consideration the fact that intentions of IP addresses change.
    #  IP address is classified as good/bad by what it says in ipdb right now, not during the experiment.

    print(observations)

    tp = 0  # correctly identified attackers
    tn = 0  # correctly identified benign ips
    fp = 0  # falsely accused benign ips
    fn = 0  # undetected attackers

    for rnd in range(0, rounds):
        rnd_data = observations[rnd]

        for observer in rnd_data.keys():
            for observed_ip in rnd_data[observer].keys():
                nscore, nconfidence, score, confidence = rnd_data[observer][observed_ip]
                print(nscore, nconfidence, score, confidence)
                gt = ipdb.ips[observed_ip].is_good

                decision = ((score * confidence) + (nscore * nconfidence)) / 2
                print(decision)
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


