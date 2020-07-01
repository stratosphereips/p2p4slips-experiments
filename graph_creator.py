import matplotlib.pyplot as plt

data0 = {"0": {"1.1.1.0": {"1.1.1.10": [-0.4, 0.21900000000000003, 0.3, 0.1]}},
         "1": {"1.1.1.0": {"1.1.1.10": [-0.8, 0.41000000000000003, 0.6, 0.2]}}, "2": {
        "1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.48499999999999993, 0.8999999999999999, 0.30000000000000004]}},
         "3": {"1.1.1.0": {"1.1.1.10": [-0.9999999999999997, 0.5499999999999999, 1.0, 0.4]}},
         "4": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.6, 1.0, 0.5]}},
         "5": {"1.1.1.0": {"1.1.1.10": [-0.9999999999999997, 0.6499999999999999, 1.0, 0.6]}},
         "6": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.7000000000000001, 1.0, 0.7]}},
         "7": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.75, 1.0, 0.7999999999999999]}},
         "8": {"1.1.1.0": {"1.1.1.10": [-0.9999999999999996, 0.7999999999999999, 1.0, 0.8999999999999999]}},
         "9": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999998, 1.0, 0.9999999999999999]}},
         "10": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, 1.0, 1.0]}},
         "11": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, 1.0, 1.0]}},
         "12": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, 1.0, 1.0]}},
         "13": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, 1.0, 1.0]}},
         "14": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, 1.0, 1.0]}},
         "15": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, -0.4, 1.0]}},
         "16": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, -0.8, 1.0]}},
         "17": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "18": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "19": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "20": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "21": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "22": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "23": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "24": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "25": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "26": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "27": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "28": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "29": {"1.1.1.0": {"1.1.1.10": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}}}

data1 = {"0": {"1.1.1.0": {"1.1.1.6": [-0.1666666666666667, 0.15816666666666665, 0.3, 0.1]}},
         "1": {"1.1.1.0": {"1.1.1.6": [-0.3333333333333334, 0.30066666666666664, 0.6, 0.2]}}, "2": {
        "1.1.1.0": {"1.1.1.6": [-0.36666666666666675, 0.3718333333333333, 0.8999999999999999, 0.30000000000000004]}},
         "3": {"1.1.1.0": {"1.1.1.6": [-0.3333333333333333, 0.43999999999999995, 1.0, 0.4]}},
         "4": {"1.1.1.0": {"1.1.1.6": [-0.33333333333333337, 0.5, 1.0, 0.5]}},
         "5": {"1.1.1.0": {"1.1.1.6": [-0.3333333333333333, 0.5633333333333332, 1.0, 0.6]}},
         "6": {"1.1.1.0": {"1.1.1.6": [-0.33333333333333337, 0.63, 1.0, 0.7]}},
         "7": {"1.1.1.0": {"1.1.1.6": [-0.3333333333333333, 0.7000000000000001, 1.0, 0.7999999999999999]}},
         "8": {"1.1.1.0": {"1.1.1.6": [-0.33333333333333326, 0.7733333333333333, 1.0, 0.8999999999999999]}},
         "9": {"1.1.1.0": {"1.1.1.6": [-0.3333333333333333, 0.8499999999999998, 1.0, 0.9999999999999999]}},
         "10": {"1.1.1.0": {"1.1.1.6": [-0.33333333333333337, 0.85, 1.0, 1.0]}},
         "11": {"1.1.1.0": {"1.1.1.6": [-0.33333333333333337, 0.85, 1.0, 1.0]}},
         "12": {"1.1.1.0": {"1.1.1.6": [-0.33333333333333337, 0.85, 1.0, 1.0]}},
         "13": {"1.1.1.0": {"1.1.1.6": [-0.33333333333333337, 0.85, 1.0, 1.0]}},
         "14": {"1.1.1.0": {"1.1.1.6": [-0.33333333333333337, 0.85, 1.0, 1.0]}},
         "15": {"1.1.1.0": {"1.1.1.6": [-0.8, 0.85, -0.4, 1.0]}},
         "16": {"1.1.1.0": {"1.1.1.6": [-0.9333333333333336, 0.85, -0.8, 1.0]}},
         "17": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.85, -1.0, 1.0]}},
         "18": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.85, -1.0, 1.0]}},
         "19": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.85, -1.0, 1.0]}},
         "20": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.85, -1.0, 1.0]}},
         "21": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.85, -1.0, 1.0]}},
         "22": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.85, -1.0, 1.0]}},
         "23": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.85, -1.0, 1.0]}},
         "24": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.85, -1.0, 1.0]}},
         "25": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.85, -1.0, 1.0]}},
         "26": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.85, -1.0, 1.0]}},
         "27": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.85, -1.0, 1.0]}},
         "28": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.85, -1.0, 1.0]}},
         "29": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.85, -1.0, 1.0]}}}

data2 = {"0": {"1.1.1.0": {"1.1.1.6": [-0.05000000000000002, 0.12775, 0.3, 0.1]}},
         "1": {"1.1.1.0": {"1.1.1.6": [-0.10000000000000003, 0.24599999999999997, 0.6, 0.2]}},
         "2": {"1.1.1.0": {"1.1.1.6": [-0.05000000000000002, 0.31525, 0.8999999999999999, 0.30000000000000004]}},
         "3": {"1.1.1.0": {"1.1.1.6": [-2.7755575615628914e-17, 0.385, 1.0, 0.4]}},
         "4": {"1.1.1.0": {"1.1.1.6": [5.551115123125783e-17, 0.45, 1.0, 0.5]}},
         "5": {"1.1.1.0": {"1.1.1.6": [-2.7755575615628914e-17, 0.52, 1.0, 0.6]}},
         "6": {"1.1.1.0": {"1.1.1.6": [5.551115123125783e-17, 0.595, 1.0, 0.7]}},
         "7": {"1.1.1.0": {"1.1.1.6": [0.0, 0.675, 1.0, 0.7999999999999999]}},
         "8": {"1.1.1.0": {"1.1.1.6": [-2.7755575615628914e-17, 0.7599999999999999, 1.0, 0.8999999999999999]}},
         "9": {"1.1.1.0": {"1.1.1.6": [0.0, 0.8499999999999998, 1.0, 0.9999999999999999]}},
         "10": {"1.1.1.0": {"1.1.1.6": [5.551115123125783e-17, 0.8499999999999999, 1.0, 1.0]}},
         "11": {"1.1.1.0": {"1.1.1.6": [5.551115123125783e-17, 0.8499999999999999, 1.0, 1.0]}},
         "12": {"1.1.1.0": {"1.1.1.6": [5.551115123125783e-17, 0.8499999999999999, 1.0, 1.0]}},
         "13": {"1.1.1.0": {"1.1.1.6": [5.551115123125783e-17, 0.8499999999999999, 1.0, 1.0]}},
         "14": {"1.1.1.0": {"1.1.1.6": [5.551115123125783e-17, 0.8499999999999999, 1.0, 1.0]}},
         "15": {"1.1.1.0": {"1.1.1.6": [-0.7000000000000001, 0.8499999999999999, -0.4, 1.0]}},
         "16": {"1.1.1.0": {"1.1.1.6": [-0.9000000000000001, 0.8499999999999999, -0.8, 1.0]}},
         "17": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "18": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "19": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "20": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "21": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "22": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "23": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "24": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "25": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "26": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "27": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "28": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}},
         "29": {"1.1.1.0": {"1.1.1.6": [-1.0000000000000002, 0.8499999999999999, -1.0, 1.0]}}}


def show_score_graphs(data, victim_name, remote_peer_ip_address):
    timeline = range(0, len(data))

    data_as_list = [data[str(i)] for i in timeline]

    score = [h[victim_name][remote_peer_ip_address][2] for h in data_as_list]
    confidence = [h[victim_name][remote_peer_ip_address][3] for h in data_as_list]
    nos = [h[victim_name][remote_peer_ip_address][0] for h in data_as_list]
    noc = [h[victim_name][remote_peer_ip_address][1] for h in data_as_list]

    plt.plot(timeline, score, color='g')
    plt.plot(timeline, confidence, color='orange')
    plt.ylim(-1.05, 1.05)
    plt.xlabel('Algorithm rounds')
    plt.ylabel('Simulated IDS output')
    plt.title('Changes in score (green) and confidence (orange) in time')
    plt.show()

    plt.plot(timeline, nos, color='g')
    plt.plot(timeline, noc, color='orange')
    plt.ylim(-1.05, 1.05)
    plt.xlabel('Algorithm rounds')
    plt.ylabel('P2P network opinion')
    plt.title('Changes in score (green) and confidence (orange) in time')
    plt.show()

    decision_ips = [s * c for s, c in zip(score, confidence)]
    decision_p2p = [ns * nc for ns, nc in zip(nos, noc)]
    decision_combined = [(s * c + ns * nc) / 2 for s, c, ns, nc in zip(score, confidence, nos, noc)]
    threshold = [-0.5 for _ in timeline]

    di_accuracy = 0
    dc_accuracy = 0
    for di, dc in zip (decision_ips, decision_combined):
        if di < -0.5:
            di_accuracy += 1
        if dc < -0.5:
            dc_accuracy += 1

    di_accuracy = di_accuracy / len(decision_ips)
    dc_accuracy = dc_accuracy / len(decision_ips)

    print(di_accuracy, dc_accuracy)

    plt.plot(timeline, decision_ips, color='g')
    plt.plot(timeline, decision_p2p, color='orange')
    plt.plot(timeline, decision_combined, color='r')
    plt.plot(timeline, threshold, color='b')
    plt.ylim(-1.05, 1.05)
    plt.xlabel('Algorithm rounds')
    plt.ylabel('Decision value')
    plt.title('Decision made by the IPS (green) P2P alone (orange) and combined (red)')
    plt.show()


show_score_graphs(data0, "1.1.1.0", "1.1.1.10")