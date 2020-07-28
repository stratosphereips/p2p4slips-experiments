# format data from the experiments to plots or tables
import matplotlib

matplotlib.use('Qt5Agg')


def visualise(detection_data):
    rounds = sorted(list(detection_data.keys()))

    observed_ips = list(detection_data[rounds[0]].keys())

    colors = {"1.1.1.10": "red", "1.1.1.11": "forestgreen"}
    linewidths = {"1.1.1.10": 5, "1.1.1.11": 2}
    alphas = {"1.1.1.10": 0.8, "1.1.1.11": 1.0}
    labels = {"1.1.1.10": "1.1.1.10", "1.1.1.11": "1.1.1.11"}

    ips_raw_detections = {ip: [detection_data[t][ip][0] for t in rounds] for ip in observed_ips}
    # print(ips_raw_detections)
    visualise_raw(ips_raw_detections, observed_ips, rounds, colors, linewidths, alphas, labels)


def visualise_raw(ips_raw_detections, ips, rounds, colors, linewidths, alphas, labels):

    for ip in ips:
        matplotlib.pyplot.plot(rounds,
                               ips_raw_detections[ip],
                               color=colors[ip],
                               linewidth=linewidths[ip],
                               alpha=alphas[ip],
                               label=labels[ip])
    matplotlib.pyplot.ylim(-1.05, 1.05)
    matplotlib.pyplot.xticks(list(range(0, 20)))
    matplotlib.pyplot.grid(True)
    matplotlib.pyplot.gca().set_aspect(4.5)
    matplotlib.pyplot.xlabel('Algorithm rounds')
    matplotlib.pyplot.ylabel('IPS detection')
    matplotlib.pyplot.legend()
    matplotlib.pyplot.show()


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


def create_enormous_table(data, skip_individual_ips=False, verbose=True):

    output_lines = []

    # expected input is data[ip1, ip2, all] = accuracy
    thresholds = list(data.keys())
    weights = list(data[thresholds[0]].keys())
    ips = ["1.1.1.10", "1.1.1.11", "all"]
    ip_names = {"1.1.1.10": "1.1.1.10", "1.1.1.11": "1.1.1.11", "all": "All"}
    cline = "\\cline{2-" + str(len(thresholds) + 2) + "}"
    thickhline = "\\thickhline"

    # prepare table width
    column_specs = "|c|c\"" + ("c|" * len(thresholds))
    output_lines.append(column_specs)

    output_lines.append(thickhline)

    # make header
    header = "\multicolumn{2}{|c\"}{\\backslashbox[26mm]{$w$}{$T$}} & " + "".join([str(t) + " & " for t in thresholds])[:-2] + "\\\\"
    output_lines.append(header)

    output_lines.append(thickhline)

    for w in weights:
        lines = {ip: "" for ip in ips}

        # initialize multiline headers
        lines[ips[0]] += "\multirow{3}{*}{" + str(w) + "} & " + ip_names[ips[0]]
        for ip in ips[1:]:
            lines[ip] += " & " + ip_names[ip]

        # fill lines with data
        for t in thresholds:
            for ip in ips:
                set_color = ip == "all"
                cell_color = get_cell_color(data[t][w][ip], set_color)
                lines[ip] += " & " + cell_color + " " + str(data[t][w][ip])

        # end lines and print them
        for ip in ips[:-1]:
            lines[ip] += "\\\\" + cline
            output_lines.append(lines[ip])

        # print last line with a thick separator
        ip = ips[-1]
        lines[ip] += "\\\\" + thickhline
        output_lines.append(lines[ip])

    if verbose:
        for line in output_lines:
            print(line)

    return output_lines


def get_cell_color(value, check=False):
    if not check or value <= 0.75:
        return ""
    if value <= 0.8:
        return "\\cellcolor{grayscale-d}"
    if value <= 0.85:
        return "\\cellcolor{grayscale-c}"
    if value <= 0.9:
        return "\\cellcolor{grayscale-b}"
    if value <= 0.95:
        return "\\cellcolor{grayscale-a}"
    return "\\cellcolor{grayscale-9}"
