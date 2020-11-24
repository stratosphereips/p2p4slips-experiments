import json
import time

import matplotlib

from p2ptrust.testing.experiments.output_processor import visualise, find_best_threshold_long_table, \
    create_enormous_table, visualise_raw



def compute_prediction(nscore, nconfidence, score, confidence, weight_ips):
    prediction = ((1 - weight_ips) * (nscore * nconfidence)) + (weight_ips * (score * confidence))
    return prediction


def evaluate(observations: dict, rounds, is_good=None, threshold=-0.5, weight_ips=0.5, show_visualisation=False,
             verbose=False):
    if is_good is None:
        is_good = {}

    observed_ips = list(is_good.keys())

    lines = {k: "" for k in is_good.keys()}
    observation_results = {k: {"FP": 0, "TP": 0, "FN": 0, "TN": 0} for k in is_good.keys()}
    predictions = {}

    for rnd in range(0, rounds):
        try:
            rnd_data = observations[rnd]
        except KeyError:
            rnd_data = observations[str(rnd)]

        predictions[rnd] = {ip: [] for ip in is_good.keys()}

        for observer in rnd_data.keys():
            for observed_ip in rnd_data[observer].keys():
                net_score, net_confidence, score, confidence = rnd_data[observer][observed_ip]
                gt = is_good[observed_ip]

                prediction = compute_prediction(net_score, net_confidence, score, confidence, weight_ips)
                predictions[rnd][observed_ip].append(prediction)

                lines[observed_ip] += " " + str(prediction)
                # print(decision)
                if prediction < threshold:
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
        visualise(predictions)

    if verbose:
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


def eval_exp_1_ips_only():
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
            accuracy = evaluate(data, 20, is_good, threshold=threshold, weight_ips=1, show_visualisation=True)
            accuracies[threshold] = accuracy

    find_best_threshold_long_table(accuracies)


def eval_exp_2a_no_malicious():
    exp_dir = "/home/dita/p2ptrust-experiments-link/experiment_data/experiments-1595614755.6837168/"
    exp_suffix = "_keep_malicious_device_unblocked"
    exp_id = 0

    is_good = {"1.1.1.10": False, "1.1.1.11": True}
    thresholds = [x / 10 for x in range(-10, 11)]
    weights = [x / 10 for x in range(0, 11)]
    accuracies = {}

    data_file = exp_dir + str(exp_id) + exp_suffix + "/round_results.txt"
    with open(data_file, "r") as f:
        data = json.load(f)
        for threshold in thresholds:
            accuracies[threshold] = {}
            for ips_weight in weights:
                print("Experiment id: " + str(exp_id) + "/10, t = " + str(threshold) + ", w = " + str(ips_weight))
                accuracy = evaluate(data, 20, is_good, threshold=threshold, weight_ips=ips_weight,
                                    show_visualisation=True)
                accuracy_processed = fptp2acc(accuracy)
                accuracies[threshold][ips_weight] = accuracy_processed
                k = 3

    create_enormous_table(accuracies)


def eval_exp_2b_no_malicious():
    exp_dir = "/home/dita/p2ptrust-experiments-link/experiment_data/experiments-1595856479.8787048_exp_2b/"
    exp_suffix = ""
    exp_id = 0

    is_good = {"1.1.1.10": False, "1.1.1.11": True}
    thresholds = [x / 10 for x in range(-10, 11)]
    weights = [x / 10 for x in range(0, 11)]
    accuracies = {}

    data_file = exp_dir + str(exp_id) + exp_suffix + "/round_results.txt"
    with open(data_file, "r") as f:
        data = json.load(f)
        for threshold in thresholds:
            accuracies[threshold] = {}
            for ips_weight in weights:
                print("Experiment id: " + str(exp_id) + "/10, t = " + str(threshold) + ", w = " + str(ips_weight))
                accuracy = evaluate(data, 20, is_good, threshold=threshold, weight_ips=ips_weight,
                                    show_visualisation=False)
                accuracy_processed = fptp2acc(accuracy)
                accuracies[threshold][ips_weight] = accuracy_processed
                k = 3

    create_enormous_table(accuracies)


def exp_2a_get_attack_curves():
    data = {'1.1.1.10':
                [-0.24, -0.8, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0,
                 -1.0, -1.0, -1.0],
            '1.1.1.11':
                [0.03, 0.12, 0.27, 0.4, 0.5, 0.6, 0.7, 0.7999999999999999, 0.8999999999999999, 0.9999999999999999, -0.4,
                 -0.8, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0]
            }

    rounds = list(range(0, 20))
    ips = ["1.1.1.10", "1.1.1.11"]

    colors = {"1.1.1.10": "red", "1.1.1.11": "orange"}
    linewidths = {"1.1.1.10": 5, "1.1.1.11": 2}
    alphas = {"1.1.1.10": 0.8, "1.1.1.11": 1.0}
    labels = {"1.1.1.10": "Another Peer", "1.1.1.11": "Observer"}

    visualise_raw(data, ips, rounds, colors, linewidths, alphas, labels)


def exp_2b_get_attack_curves():
    data = {'1.1.1.10':
                [-0.24, -0.8, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0,
                 -1.0, -1.0, -1.0],
            '1.1.1.11':
                [0.03, 0.12, 0.27, 0.4, 0.5, 0.6, 0.7, 0.7999999999999999, 0.8999999999999999, 0.9999999999999999, -0.4,
                 -0.8, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0, -1.0]
            }

    rounds = list(range(0, 20))
    ips = ["1.1.1.10", "1.1.1.11"]

    colors = {"1.1.1.10": "red", "1.1.1.11": "orange"}
    linewidths = {"1.1.1.10": 5, "1.1.1.11": 2}
    alphas = {"1.1.1.10": 0.8, "1.1.1.11": 1.0}
    labels = {"1.1.1.10": "Other Peers", "1.1.1.11": "Observer"}

    visualise_raw(data, ips, rounds, colors, linewidths, alphas, labels)


def fptp2acc(data: dict):
    """ Convert TP/FP/TN/TP counts to accuracy for each IP, and also combined"""
    # expected data is data[ip1, ip2][fp, tp, fn, tn] = number of occurences
    # expected output is output[ip1, ip2, all] = accuracy

    output = {}
    success_t = 0
    total_t = 0

    for ip, ip_data in data.items():
        success_i = ip_data["TP"] + ip_data["TN"]
        total_i = ip_data["TP"] + ip_data["TN"] + ip_data["FP"] + ip_data["FN"]
        success_t += success_i
        total_t += total_i
        accuracy = success_i / total_i
        output[ip] = accuracy

    accuracy = success_t / total_t
    output["all"] = accuracy

    return output


def get_accuracy_matrix_from_results(exp_folder, thresholds=None, weights=None, is_good=None):
    if is_good is None:
        is_good = {"1.1.1.10": False, "1.1.1.11": True}

    if thresholds is None:
        thresholds = [x / 10 for x in range(-10, 11)]

    if weights is None:
        weights = [x / 10 for x in range(0, 11)]

    accuracies = {}
    data_file = exp_folder + "/round_results.txt"
    with open(data_file, "r") as f:
        data = json.load(f)
        for threshold in thresholds:
            accuracies[threshold] = {}
            for ips_weight in weights:
                accuracy = evaluate(data, 20, is_good, threshold=threshold, weight_ips=ips_weight,
                                    show_visualisation=False)
                accuracy_processed = fptp2acc(accuracy)
                accuracies[threshold][ips_weight] = accuracy_processed

    return accuracies


def get_min_accuracy_matrix(accuracy_matrix, min_accuracy_matrix=None, thresholds=None, weights=None, is_good=None):
    if is_good is None:
        is_good = {"1.1.1.10": False, "1.1.1.11": True, "all": None}
    if thresholds is None:
        thresholds = [x / 10 for x in range(-10, 11)]
    if weights is None:
        weights = [x / 10 for x in range(0, 11)]

    output = {}
    for t in thresholds:
        output[t] = {}
        for w in weights:
            output[t][w] = {}
            for ip in is_good:
                try:
                    best_so_far = min_accuracy_matrix[t][w][ip]
                except:
                    best_so_far = 1.0
                output[t][w][ip] = min(best_so_far, accuracy_matrix[t][w][ip])

    return output


def get_max_accuracy_matrix(accuracy_matrix, max_accuracy_matrix=None, thresholds=None, weights=None, is_good=None):
    if is_good is None:
        is_good = {"1.1.1.10": False, "1.1.1.11": True, "all": None}
    if thresholds is None:
        thresholds = [x / 10 for x in range(-10, 11)]
    if weights is None:
        weights = [x / 10 for x in range(0, 11)]

    output = {}
    for t in thresholds:
        output[t] = {}
        for w in weights:
            output[t][w] = {}
            for ip in is_good:
                try:
                    best_so_far = max_accuracy_matrix[t][w][ip]
                except:
                    best_so_far = 0.0
                output[t][w][ip] = max(best_so_far, accuracy_matrix[t][w][ip])
                if w > 0.95 and output[t][w][ip] > 0.75 and ip == "all":
                    # print(t, w, ip, output[t][w][ip])
                    k = 3

    return output


def add_accuracies(a, b):
    output = {}
    for t in a.keys():  # threshold
        output[t] = {}
        for w in a[t].keys():  # weight
            output[t][w] = {}
            for ip in a[t][w].keys():  # ip
                if a[t][w][ip] < 0.75:
                    output[t][w][ip] = 0
                else:
                    output[t][w][ip] = round(a[t][w][ip] + b[t][w][ip], 4)

    return output


def generate_prediction_graph_for_2a(threshold=0, ips_weight=0.4):
    exp_dir = "/home/dita/p2ptrust-experiments-link/experiment_data/experiments-1595614755.6837168/"
    exp_suffix = "_keep_malicious_device_unblocked"
    exp_id = 0

    is_good = {"1.1.1.10": False, "1.1.1.11": True}
    accuracies = {}

    data_file = exp_dir + str(exp_id) + exp_suffix + "/round_results.txt"
    with open(data_file, "r") as f:
        data = json.load(f)
        print("Experiment id: " + str(exp_id) + "/10, t = " + str(threshold) + ", w = " + str(ips_weight))
        evaluate(data, 20, is_good, threshold=threshold, weight_ips=ips_weight, show_visualisation=True)


def plot_ips_demo():
    # predictions = {
    #     '1.1.1.1': [-0.24, -0.8, -1.0, 0.0, 0.0, 0.0, 0.0, 0.05, 0.16000000000000003, 0.30000000000000004, 0.4, 0.5,
    #                 0.6, 0.7, 0.7999999999999999, 0.8999999999999999, 0.9999999999999999, 1.0, 1.0, 1.0],
    #     '1.1.1.2': [0.03, -0.27999999999999997, -0.8, -1.0, 0.0, 0.0, 0.0, 0.0, 0.05, 0.16000000000000003,
    #                 0.30000000000000004, 0.4, 0.5, 0.6, 0.7, 0.7999999999999999, 0.8999999999999999, 0.9999999999999999,
    #                 1.0, 1.0],
    #     '1.1.1.3': [0.03, 0.12, -0.32000000000000006, -0.8, -1.0, 0.0, 0.0, 0.0, 0.0, 0.05, 0.16000000000000003,
    #                 0.30000000000000004, 0.4, 0.5, 0.6, 0.7, 0.7999999999999999, 0.8999999999999999, 0.9999999999999999,
    #                 1.0],
    #     '1.1.1.4': [0.03, 0.12, 0.27, -0.36000000000000004, -0.8, -1.0, 0.0, 0.0, 0.0, 0.0, 0.05, 0.16000000000000003,
    #                 0.30000000000000004, 0.4, 0.5, 0.6, 0.7, 0.7999999999999999, 0.8999999999999999,
    #                 0.9999999999999999],
    #     '1.1.1.5': [0.03, 0.12, 0.27, 0.4, -0.4, -0.8, -1.0, 0.0, 0.0, 0.0, 0.0, 0.05, 0.16000000000000003,
    #                 0.30000000000000004, 0.4, 0.5, 0.6, 0.7, 0.7999999999999999, 0.8999999999999999],
    #     '1.1.1.6': [0.03, 0.12, 0.27, 0.4, 0.5, -0.4, -0.8, -1.0, 0.0, 0.0, 0.0, 0.0, 0.05, 0.16000000000000003,
    #                 0.30000000000000004, 0.4, 0.5, 0.6, 0.7, 0.7999999999999999],
    #     '1.1.1.7': [0.03, 0.12, 0.27, 0.4, 0.5, 0.6, -0.4, -0.8, -1.0, 0.0, 0.0, 0.0, 0.0, 0.05, 0.16000000000000003,
    #                 0.30000000000000004, 0.4, 0.5, 0.6, 0.7],
    #     '1.1.1.8': [0.03, 0.12, 0.27, 0.4, 0.5, 0.6, 0.7, -0.4, -0.8, -1.0, 0.0, 0.0, 0.0, 0.0, 0.05,
    #                 0.16000000000000003, 0.30000000000000004, 0.4, 0.5, 0.6],
    #     '1.1.1.9': [0.03, 0.12, 0.27, 0.4, 0.5, 0.6, 0.7, 0.7999999999999999, -0.4, -0.8, -1.0, 0.0, 0.0, 0.0, 0.0,
    #                 0.05, 0.16000000000000003, 0.30000000000000004, 0.4, 0.5]}
    # scores = {
    #     '1.1.1.1': [-0.4, -0.8, -1.0, -0.7, -0.39999999999999997, -0.09999999999999998, 0.2, 0.5, 0.8, 1.0, 1.0, 1.0,
    #                 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
    #     '1.1.1.2': [0.3, -0.4, -0.8, -1.0, -0.7, -0.39999999999999997, -0.09999999999999998, 0.2, 0.5, 0.8, 1.0, 1.0,
    #                 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
    #     '1.1.1.3': [0.3, 0.6, -0.4, -0.8, -1.0, -0.7, -0.39999999999999997, -0.09999999999999998, 0.2, 0.5, 0.8, 1.0,
    #                 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
    #     '1.1.1.4': [0.3, 0.6, 0.8999999999999999, -0.4, -0.8, -1.0, -0.7, -0.39999999999999997, -0.09999999999999998,
    #                 0.2, 0.5, 0.8, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
    #     '1.1.1.5': [0.3, 0.6, 0.8999999999999999, 1.0, -0.4, -0.8, -1.0, -0.7, -0.39999999999999997,
    #                 -0.09999999999999998, 0.2, 0.5, 0.8, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
    #     '1.1.1.6': [0.3, 0.6, 0.8999999999999999, 1.0, 1.0, -0.4, -0.8, -1.0, -0.7, -0.39999999999999997,
    #                 -0.09999999999999998, 0.2, 0.5, 0.8, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
    #     '1.1.1.7': [0.3, 0.6, 0.8999999999999999, 1.0, 1.0, 1.0, -0.4, -0.8, -1.0, -0.7, -0.39999999999999997,
    #                 -0.09999999999999998, 0.2, 0.5, 0.8, 1.0, 1.0, 1.0, 1.0, 1.0],
    #     '1.1.1.8': [0.3, 0.6, 0.8999999999999999, 1.0, 1.0, 1.0, 1.0, -0.4, -0.8, -1.0, -0.7, -0.39999999999999997,
    #                 -0.09999999999999998, 0.2, 0.5, 0.8, 1.0, 1.0, 1.0, 1.0],
    #     '1.1.1.9': [0.3, 0.6, 0.8999999999999999, 1.0, 1.0, 1.0, 1.0, 1.0, -0.4, -0.8, -1.0, -0.7, -0.39999999999999997,
    #                 -0.09999999999999998, 0.2, 0.5, 0.8, 1.0, 1.0, 1.0]}
    # confidences = {'1.1.1.1': [0.6, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.1, 0.2, 0.30000000000000004, 0.4, 0.5, 0.6, 0.7,
    #                            0.7999999999999999, 0.8999999999999999, 0.9999999999999999, 1.0, 1.0, 1.0],
    #                '1.1.1.2': [0.1, 0.7, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.1, 0.2, 0.30000000000000004, 0.4, 0.5, 0.6,
    #                            0.7, 0.7999999999999999, 0.8999999999999999, 0.9999999999999999, 1.0, 1.0],
    #                '1.1.1.3': [0.1, 0.2, 0.8, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.1, 0.2, 0.30000000000000004, 0.4, 0.5,
    #                            0.6, 0.7, 0.7999999999999999, 0.8999999999999999, 0.9999999999999999, 1.0],
    #                '1.1.1.4': [0.1, 0.2, 0.30000000000000004, 0.9, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.1, 0.2,
    #                            0.30000000000000004, 0.4, 0.5, 0.6, 0.7, 0.7999999999999999, 0.8999999999999999,
    #                            0.9999999999999999],
    #                '1.1.1.5': [0.1, 0.2, 0.30000000000000004, 0.4, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.1, 0.2,
    #                            0.30000000000000004, 0.4, 0.5, 0.6, 0.7, 0.7999999999999999, 0.8999999999999999],
    #                '1.1.1.6': [0.1, 0.2, 0.30000000000000004, 0.4, 0.5, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.1, 0.2,
    #                            0.30000000000000004, 0.4, 0.5, 0.6, 0.7, 0.7999999999999999],
    #                '1.1.1.7': [0.1, 0.2, 0.30000000000000004, 0.4, 0.5, 0.6, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.1,
    #                            0.2, 0.30000000000000004, 0.4, 0.5, 0.6, 0.7],
    #                '1.1.1.8': [0.1, 0.2, 0.30000000000000004, 0.4, 0.5, 0.6, 0.7, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0,
    #                            0.1, 0.2, 0.30000000000000004, 0.4, 0.5, 0.6],
    #                '1.1.1.9': [0.1, 0.2, 0.30000000000000004, 0.4, 0.5, 0.6, 0.7, 0.7999999999999999, 1.0, 1.0, 1.0,
    #                            0.0, 0.0, 0.0, 0.0, 0.1, 0.2, 0.30000000000000004, 0.4, 0.5]}

    detections = {
        '1.1.1.1': [-0.24, -0.8, -1.0, 0.0, 0.0, 0.0, 0.0, 0.05, 0.16000000000000003, 0.30000000000000004, 0.4, 0.5,
                    0.6, 0.7, 0.7999999999999999, 0.8999999999999999, 0.9999999999999999, 1.0, 1.0, 1.0],
        '1.1.1.9': [0.03, 0.12, 0.27, 0.4, 0.5, 0.6, 0.7, 0.7999999999999999, -0.4, -0.8, -1.0, 0.0, 0.0, 0.0, 0.0,
                    0.05, 0.16000000000000003, 0.30000000000000004, 0.4, 0.5]}
    scores = {
        '1.1.1.1': [-0.4, -0.8, -1.0, -0.7, -0.39999999999999997, -0.09999999999999998, 0.2, 0.5, 0.8, 1.0, 1.0, 1.0,
                    1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
        '1.1.1.9': [0.3, 0.6, 0.8999999999999999, 1.0, 1.0, 1.0, 1.0, 1.0, -0.4, -0.8, -1.0, -0.7, -0.39999999999999997,
                    -0.09999999999999998, 0.2, 0.5, 0.8, 1.0, 1.0, 1.0]}
    confidences = {'1.1.1.1': [0.6, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.1, 0.2, 0.30000000000000004, 0.4, 0.5, 0.6, 0.7,
                               0.7999999999999999, 0.8999999999999999, 0.9999999999999999, 1.0, 1.0, 1.0],
                   '1.1.1.9': [0.1, 0.2, 0.30000000000000004, 0.4, 0.5, 0.6, 0.7, 0.7999999999999999, 1.0, 1.0, 1.0,
                               0.0, 0.0, 0.0, 0.0, 0.1, 0.2, 0.30000000000000004, 0.4, 0.5]}

    rounds = list(range(0, 20))
    ips = ["1.1.1.9"]

    colors = {"1.1.1.1": "red", "1.1.1.9": "orange"}
    labels = {"1.1.1.1": "Attacked right away", "1.1.1.9": "Attacked at round 9"}

    visualise_ips(detections, scores, confidences, ips, rounds, colors, labels)


def visualise_ips_and_omega_in_experiment(exp_name, subfolder_name, ips_weight):
    data_folder = "/home/dita/p2ptrust-experiments-link/experiment_outputs/exp_" + exp_name + "/" + subfolder_name

    data_file = data_folder + "/round_results.txt"

    rounds = list(range(0, 20))
    detections = {"1.1.1.10": [], "1.1.1.11": []}
    omegas = {"1.1.1.10": [], "1.1.1.11": []}
    predictions = {"1.1.1.10": [], "1.1.1.11": []}
    with open(data_file, "r") as f:
        data = json.load(f)
        for round in data.keys():
            rnd_data = data[round]
            for observer in rnd_data.keys():
                for observed_ip in rnd_data[observer].keys():
                    net_score, net_confidence, score, confidence = rnd_data[observer][observed_ip]
                    ips_detection = score * confidence
                    omega = net_confidence * net_score
                    prediction = compute_prediction(net_score, net_confidence, score, confidence, ips_weight)
                    detections[observed_ip].append(ips_detection)
                    omegas[observed_ip].append(omega)
                    predictions[observed_ip].append(prediction)

        colors = {"1.1.1.10": "red", "1.1.1.11": "green"}
        label_suffix = {"1.1.1.10": "malicious device", "1.1.1.11": "benign device"}
        for ip in ["1.1.1.11", "1.1.1.10"]:
            matplotlib.pyplot.plot(rounds,
                                   omegas[ip],
                                   color=colors[ip],
                                   linestyle=":",
                                   label="P2P_detection for the " + label_suffix[ip])
            matplotlib.pyplot.plot(rounds,
                                   detections[ip],
                                   color=colors[ip],
                                   linestyle="--",
                                   label="IPS_detection for the " + label_suffix[ip])
            if 0 <= ips_weight <= 1:
                matplotlib.pyplot.plot(rounds,
                                       predictions[ip],
                                       color=colors[ip],
                                       label="Prediction for the " + label_suffix[ip])
        matplotlib.pyplot.ylim(-1.05, 1.05)
        matplotlib.pyplot.xticks(list(range(0, 20)))
        matplotlib.pyplot.grid(True)
        matplotlib.pyplot.gca().set_aspect(4.5)
        matplotlib.pyplot.xlabel('Experiment rounds')
        matplotlib.pyplot.ylabel('IPS_detections, P2P_detections and predictions')
        matplotlib.pyplot.legend()
        matplotlib.pyplot.show()


def visualise_ips(detections, scores, confidences, ips, rounds, colors, labels):

    for ip in ips:
        matplotlib.pyplot.plot(rounds,
                               detections[ip],
                               color=colors[ip],
                               label="IPS_detection")
        matplotlib.pyplot.plot(rounds,
                               scores[ip],
                               color="red",
                               linestyle=":",
                               label="Score")
        matplotlib.pyplot.plot(rounds,
                               confidences[ip],
                               color="forestgreen",
                               linestyle="--",
                               label="Confidence")
    matplotlib.pyplot.ylim(-1.05, 1.05)
    matplotlib.pyplot.xticks(list(range(0, 20)))
    matplotlib.pyplot.grid(True)
    matplotlib.pyplot.gca().set_aspect(4.5)
    matplotlib.pyplot.xlabel('Experiment rounds')
    matplotlib.pyplot.ylabel('IPS_detection, score, confidence')
    matplotlib.pyplot.legend()
    matplotlib.pyplot.show()


def run_ips_sim_for_2b():
    exp_name = "_ips_sim"
    timestamp = str(time.time())
    timestamp = "1595842634.7445016"
    # for peer_id in range(1, 10):
    #     config, queue, queue_thread, base_dir = init_experiments(dirname, timestamp=timestamp)
    #     s = Setups(base_dir)
    #     attack_plan = {}
    #     for i in range(0, 20):
    #         targets = []
    #         if abs(peer_id - i) <= 1:
    #             targets.append("1.1.1.0")
    #         attack_plan[i] = targets
    #     ctrl = s.attack_observer_no_peers(queue, config, exp_id=peer_id, attack_plan=attack_plan, exp_name=exp_name)
    #     ctrl.run_experiment_ids_only()
    #     queue_thread.kill()
    #     time.sleep(10)

    # a directory dirname was created, all data is there
    predictions_in_peers = {}
    scores_in_peers = {}
    confidences_in_peers = {}
    colors = {}
    ips = []
    # TODO fix dirname
    dirname=""
    cmap = matplotlib.cm.get_cmap('OrRd')
    for peer_id in range(1, 10):
        peer_ip = "1.1.1." + str(peer_id)
        colors[peer_ip] = cmap(peer_id / 15 + 0.3)
        predictions_in_peers[peer_ip] = []
        scores_in_peers[peer_ip] = []
        confidences_in_peers[peer_ip] = []
        ips.append(peer_ip)
        exp_file = dirname + timestamp + "/" + str(peer_id) + exp_name + "round_results.txt"
        with open(exp_file, "r") as f:
            data = json.load(f)
            rounds = sorted(list(map(int, data.keys())))
            for r in rounds:
                net_score, net_confidence, score, confidence = data[str(r)]["1.1.1.0"]["1.1.1.10"]
                prediction = compute_prediction(net_score, net_confidence, score, confidence, 1)
                predictions_in_peers[peer_ip].append(prediction)
                scores_in_peers[peer_ip].append(score)
                confidences_in_peers[peer_ip].append(confidence)

    line_widths = {ip: 2 for ip in ips}
    alphas = {ip: 1 for ip in ips}
    labels = {ip: ip for ip in ips}

    print(predictions_in_peers)
    print(scores_in_peers)
    print(confidences_in_peers)

    visualise_raw(predictions_in_peers, ips, rounds, colors, line_widths, alphas, labels)


def make_all_graphs():
    # 05-ips-simulation-2.pdf
    plot_ips_demo()

    #07-exp1-ips-only-1.pdf
    eval_exp_2a_no_malicious()

    # 07-exp2a-ips-in-other-peers.pdf
    exp_2a_get_attack_curves()

    # 07-exp2a-t0-w04.pdf
    generate_prediction_graph_for_2a()

    # 07-exp2b-ips-in-all-peers.pdf
    run_ips_sim_for_2b()

    # 07-exp5a1.pdf
    visualise_ips_and_omega_in_experiment("5a", "1", -1)

    # 07-exp4a6-hole-explanation.pdf
    visualise_ips_and_omega_in_experiment("4a", "6", 0.3)


if __name__ == '__main__':
    # exp_dir = "/home/dita/p2ptrust-experiments-link/experiment_data/experiments-1594842957.0396457/"
    # exp_suffix = "_badmouth_good_device"
    # exp_dir = "/home/dita/p2ptrust-experiments-link/experiment_data/experiments-1594815406.4306164_/"
    # exp_suffix = "_keep_malicious_device_unblocked"

    # eval_exp_2a_no_malicious()
    # exp_2a_get_attack_curves()
    # eval_exp_1_ips_only()

    # run_ips_sim_for_2b()
    # eval_exp_2b_no_malicious()
    # exp_2b_get_attack_curves()

    # generate_prediction_graph_for_2a()
    # plot_ips_demo()

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

    # exp_2a_get_attack_curves()
    plot_ips_demo()

