import json
import matplotlib

matplotlib.use('Qt5Agg')

def compute_detection(nscore, nconfidence, score, confidence, weight_ips):
    detection = ((1 - weight_ips) * (nscore * nconfidence)) + (weight_ips * (score * confidence))
    return detection


def evaluate(observations: dict, rounds, is_good=None, threshold=-0.5, weight_ips=0.5, show_visualisation=False):

    if is_good is None:
        is_good = {}

    observed_ips = list(is_good.keys())

    lines = {k: "" for k in is_good.keys()}
    observation_results = {k: {"FP": 0, "TP": 0, "FN": 0, "TN": 0} for k in is_good.keys()}
    decisions = {}

    for rnd in range(0, rounds):
        try:
            rnd_data = observations[rnd]
        except KeyError:
            rnd_data = observations[str(rnd)]

        decisions[rnd] = {ip: [] for ip in is_good.keys()}

        for observer in rnd_data.keys():
            for observed_ip in rnd_data[observer].keys():
                net_score, net_confidence, score, confidence = rnd_data[observer][observed_ip]
                gt = is_good[observed_ip]

                decision = compute_detection(net_score, net_confidence, score, confidence, weight_ips)
                decisions[rnd][observed_ip].append(decision)

                lines[observed_ip] += " " + str(decision)
                # print(decision)
                if decision < threshold:
                    # we say it is an attacker
                    if gt:
                        result = "FP"  # we are wrong
                    else:
                        result = "TP"  # we are right
                else:
                    # we say he is benign
                    if gt:
                        result = "TN"  # we are right
                    else:
                        result = "FN"  # we are wrong

                observation_results[observed_ip][result] += 1
                lines[observed_ip] += result

    if show_visualisation:
        visualise(decisions)

    print(lines[observed_ips[0]])
    print(lines[observed_ips[1]])

    return observation_results


def eval_one_exp(exp_dir, exp_id, exp_suffix, is_good):
        thresholds = [x / 10 for x in range(-10, 11)]

        accuracies = {}
        for t in thresholds:
            accuracies[t] = []

        data_file = exp_dir + str(exp_id) + exp_suffix + "/round_results.txt"
        with open(data_file, "r") as f:
            data = json.load(f)
            for threshold in thresholds:
                print("Experiment id: " + str(exp_id) + "/10, threshold = " + str(threshold))
                accuracy = evaluate(data, 20, is_good, threshold=threshold)
                accuracies[threshold].append(accuracy)

        find_best_threshold_long_table(accuracies)


def find_best_threshold_wide_table(observation_results: dict):
    thresholds = sorted(list(observation_results.keys()))
    first_threshold = thresholds[0]
    observed_ips = list(observation_results[first_threshold].keys())

    lines = {observed_ip: str(observed_ip) + " & " for observed_ip in observed_ips}

    lines["all"] = "All & "

    thresholds_line = "".join([str(t) + " & " for t in thresholds])


    for threshold in thresholds:
        success_t = 0
        total_t = 0
        for observed_ip in observed_ips:
            x = observation_results[threshold][observed_ip]  # alias
            success_i = x["TP"] + x["TN"]
            total_i = x["TP"] + x["TN"] + x["FP"] + x["FN"]
            success_t += success_i
            total_t += total_i
            accuracy = success_i/total_i
            lines[observed_ip] += str(accuracy) + " & "

        accuracy = success_t / total_t
        lines["all"] += str(accuracy) + " & "

    print("Thresholds" + thresholds_line[:-2] + "\\\\")
    print("\\hline")
    for ip in lines.keys():
        print(lines[ip][:-2] + "\\\\")
        print("\\hline")


def find_best_threshold_long_table(observation_results: dict):
    thresholds = sorted(list(observation_results.keys()))
    first_threshold = thresholds[0]
    observed_ips = list(observation_results[first_threshold].keys())

    lines = {observed_ip: str(observed_ip) + " & " for observed_ip in observed_ips}

    lines["all"] = "All & "

    thresholds_line = "".join([str(t) + " & " for t in thresholds])

    top_line = "Threshold & " + "".join([ip + " & " for ip in observed_ips]) + "All \\\\"
    print(top_line)
    print("\\hline")
    print("\\hline")

    for threshold in thresholds:
        success_t = 0
        total_t = 0

        t_line = ""
        t_line += str(threshold) + " & "
        for observed_ip in observed_ips:
            x = observation_results[threshold][observed_ip]  # alias
            success_i = x["TP"] + x["TN"]
            total_i = x["TP"] + x["TN"] + x["FP"] + x["FN"]
            success_t += success_i
            total_t += total_i
            accuracy = success_i/total_i
            t_line += str(accuracy) + " & "

        accuracy = success_t / total_t
        t_line += str(accuracy) + " \\\\"
        print(t_line)
        print("\\hline")


    #
    # print("Threshold & Accuracy \\\\")
    # print("\\hline")
    # for t in observation_results.keys():
    #     print("\\hline")
    #     print(str(t) + " & " + str(observation_results[t]) + " \\\\")
    # print("\\hline")


def eval_exp_ips_only():
    exp_dir = "/home/dita/p2ptrust-experiments-link/experiment_data/experiments-1595614755.6837168/"
    exp_suffix = "_keep_malicious_device_unblocked"
    exp_id = 0

    is_good = {"1.1.1.10": False, "1.1.1.11": True}
    thresholds = [x / 10 for x in range(-10, 11)]
    accuracies = {}

    data_file = exp_dir + str(exp_id) + exp_suffix + "/round_results.txt"
    with open(data_file, "r") as f:
        data = json.load(f)
        for threshold in thresholds:
            print("Experiment id: " + str(exp_id) + "/10, threshold = " + str(threshold))
            accuracy = evaluate(data, 20, is_good, threshold=threshold, weight_ips=1)
            accuracies[threshold] = accuracy

    find_best_threshold_long_table(accuracies)


def visualise(detection_data):
    thresholds = sorted(list(detection_data.keys()))

    observed_ips = list(detection_data[thresholds[0]].keys())

    colors = {"1.1.1.10": "red", "1.1.1.11": "forestgreen"}
    linewidths = {"1.1.1.10": 5, "1.1.1.11": 2}
    alphas = {"1.1.1.10": 0.8, "1.1.1.11": 1.0}

    ips_raw_detections = {ip: [detection_data[t][ip][0] for t in thresholds] for ip in observed_ips}

    for ip in observed_ips:
        matplotlib.pyplot.plot(thresholds,
                               ips_raw_detections[ip],
                               color=colors[ip],
                               linewidth=linewidths[ip],
                               alpha=alphas[ip],
                               label=ip)
    matplotlib.pyplot.ylim(-1.05, 1.05)
    matplotlib.pyplot.xticks(list(range(0, 20)))
    matplotlib.pyplot.grid(True)
    matplotlib.pyplot.gca().set_aspect(4.5)
    matplotlib.pyplot.xlabel('Algorithm rounds')
    matplotlib.pyplot.ylabel('IPS detection')
    matplotlib.pyplot.legend()
    matplotlib.pyplot.show()


if __name__ == '__main__':
    exp_dir = "/home/dita/p2ptrust-experiments-link/experiment_data/experiments-1594842957.0396457/"
    exp_suffix = "_badmouth_good_device"
    exp_dir = "/home/dita/p2ptrust-experiments-link/experiment_data/experiments-1594815406.4306164_/"
    exp_suffix = "_keep_malicious_device_unblocked"

    observed_results_ = eval_exp_ips_only()

    # exp_dir = "/home/dita/p2ptrust-experiments-link/experiment_data/experiments-1595605824.1189618/"
    # exp_suffix = "_attacker_targeting_different_amounts_of_peers"

    # is_good = {"1.1.1.10": False, "1.1.1.11": True}
    #
    # eval_one_exp(exp_dir, 0, exp_suffix, is_good)

    # thresholds = [x/10 for x in range(-10, 10)]
    #
    # accuracies = {}
    # for t in thresholds:
    #     accuracies[t] = []
    #
    # for i in range(0, 10):
    #     # the following is correct, but overly complex, as I only ever check 1.1.1.10 :D
    #     # is_good = {"1.1.1." + str(10 - j): True if i < 10 - j else False for j in range(1, 11)}
    #     data_file = exp_dir + str(i) + exp_suffix + "/round_results.txt"
    #     setup_accuracies = {}
    #     with open(data_file, "r") as f:
    #         data = json.load(f)
    #         for threshold in thresholds:
    #             print("Number of malicious peers: " + str(i) + "/10, threshold = " + str(threshold))
    #             accuracy = evaluate(data, None, 20, is_good, threshold=threshold)
    #             accuracies[threshold].append(accuracy)
    #
    # find_best_threshold(accuracies)
