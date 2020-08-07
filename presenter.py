import os
import sys

from p2ptrust.testing.experiments.evaluator import get_accuracy_matrix_from_results, get_min_accuracy_matrix, \
    get_max_accuracy_matrix, add_accuracies
from p2ptrust.testing.experiments.output_processor import create_enormous_table, lists_to_table


def generate_tables(experiments=None):
    exp_location = "/home/dita/p2ptrust-experiments-link/experiment_outputs/"
    exp_prefix = "exp"
    if experiments is None:
        experiments = ["2a", "2b", "2c", "3a", "3b", "4a"]

    tables_output_location = "/home/dita/p2ptrust-experiments-link/experiment_outputs/tables/"
    tables_output_name = tables_output_location + "output_combined.tex"

    file = open(tables_output_name, "w")

    exp_base = exp_location + exp_prefix + "_"

    min_accuracy_matrix = None
    max_accuracy_matrix = None

    for exp_suffix in experiments:
        exp_folder = exp_base + exp_suffix

        exp_table_folder = tables_output_location + exp_prefix + exp_suffix + "/"
        if not os.path.exists(exp_table_folder):
            os.mkdir(exp_table_folder)

        try:
            exp_folder_walk = list(os.walk(exp_folder))[0]
        except IndexError:
            continue

        subfolders = sorted(exp_folder_walk[1])
        for subfolder_name in subfolders:

            if int(subfolder_name) < 6:
                if not exp_suffix.startswith("2"):
                    continue

            # print("Generating tables for experiment %s, run %s" % (exp_suffix, subfolder_name))
            subfolder = exp_folder + "/" + subfolder_name
            accuracy_matrix = get_accuracy_matrix_from_results(subfolder)
            min_accuracy_matrix = get_min_accuracy_matrix(accuracy_matrix, min_accuracy_matrix)
            max_accuracy_matrix = get_max_accuracy_matrix(accuracy_matrix, max_accuracy_matrix)
            k = 1

            table_lines_short = create_enormous_table(accuracy_matrix, skip_individual_ips=True, verbose=False)
            k = 3
            file.write("% " + exp_suffix + ", experiment id " + subfolder_name + ", short\n")
            file.writelines(["%s\n" % line for line in table_lines_short])
            file.write("\n")
            file.write("\n")

            short_file = open(exp_table_folder + exp_suffix + subfolder_name + "-short.tex", "w")
            short_file.writelines(["%s\n" % line for line in table_lines_short])
            short_file.close()

            table_lines_long = create_enormous_table(accuracy_matrix, skip_individual_ips=False, verbose=False,
                                                     param_threshold=0.3, param_weight=0.4,
                                                     param_name=(exp_suffix + subfolder_name))
            file.write("% " + exp_suffix + ", experiment id " + subfolder_name + ", long\n")
            file.writelines(["%s\n" % line for line in table_lines_long])
            file.write("\n")
            file.write("\n")

            long_file = open(exp_table_folder + exp_suffix + subfolder_name + "-long.tex", "w")
            long_file.writelines(["%s\n" % line for line in table_lines_long])
            short_file.close()
    table_lines_long = create_enormous_table(min_accuracy_matrix, skip_individual_ips=False, verbose=True)
    table_lines_long = create_enormous_table(max_accuracy_matrix, skip_individual_ips=False, verbose=True)

    combined_results = add_accuracies(min_accuracy_matrix, max_accuracy_matrix)
    table_lines_long = create_enormous_table(combined_results, skip_individual_ips=True, verbose=True, scale=2)

    file.close()


def generate_table_imports(exp_base="2c", iter1=None, iter2=None, blacklist=None, long=False):
    if iter1 is None:
        iter1 = [str(i) for i in range(1, 10)]
    if iter2 is None:
        iter2 = [""]
    if blacklist is None:
        blacklist = []

    output_lines = []
    for i in iter1:
        for j in iter2:
            if i + j in blacklist:
                continue
            exp_name = exp_base + i + j

            if long:
                input_file = "Tables/exp" + exp_base + "/" + exp_name + "-long"
                caption = exp_name
                label = "tab:" + exp_name + "-long"
            else:
                input_file = "Tables/exp" + exp_base + "/" + exp_name + "-short"
                caption = exp_name + ". For detailed accuracy, see \\autoref{tab:" + exp_name + "-long}."
                label = "tab:" + exp_name

            output_lines.append("\\begin{table}[ht]")
            output_lines.append("    \\centering")
            output_lines.append("    \\input{" + input_file + "} % enormous table data here")
            output_lines.append("    \\caption{" + caption + "}")
            output_lines.append("    \\label{" + label + "}")
            output_lines.append("\\end{table}")
            output_lines.append("")
            output_lines.append("")

    for line in output_lines:
        print(line)


def show_best_params():
    data = [["experiment name", "$t=0.3, w=0.4$", "$t=0.3, w=0.5$", "$t=0.3, w=0.6$"], ["2A0", "0.9", "0.925", "0.925"],
            ["2B0", "0.85", "0.825", "0.775"], ["2C1", "0.75", "0.775", "0.75"], ["2C2", "0.75", "0.775", "0.75"],
            ["2C3", "0.775", "0.775", "0.775"], ["2C4", "0.8", "0.8", "0.775"], ["2C5", "0.85", "0.825", "0.8"],
            ["2C6", "0.9", "0.875", "0.825"], ["2C7", "0.9", "0.925", "0.85"], ["2C8", "0.9", "0.925", "0.9"],
            ["3A6", "0.875", "0.825", "0.8"], ["3A7", "0.925", "0.875", "0.825"], ["3A8", "0.925", "0.925", "0.85"],
            ["3A9", "0.925", "0.925", "0.9"], ["3B6", "0.825", "0.8", "0.775"], ["3B7", "0.85", "0.825", "0.775"],
            ["3B8", "0.85", "0.825", "0.775"], ["3B9", "0.875", "0.825", "0.775"], ["4A6", "0.8", "0.775", "0.775"],
            ["4A7", "0.875", "0.85", "0.8"], ["4A8", "0.9", "0.9", "0.85"], ["4A9", "0.9", "0.9", "0.9"]]
    lists_to_table(data)


def explore_4a3():
    exp_location = "/home/dita/p2ptrust-experiments-link/experiment_outputs/exp_4a/3"
    accuracy_matrix = get_accuracy_matrix_from_results(exp_location)


# show_best_params()
# explore_4a3()

# generate_tables()
# generate_table_imports(exp_base="3b", long=False)
# generate_table_imports(exp_base="4a", long=False)
# generate_table_imports(exp_base="4a", long=True)
generate_tables(experiments=["3c"])
generate_table_imports(exp_base="3c", iter1=["11", "12", "13", "14", "15", "16", "17", "18", "22", "23", "24", "25", "26", "27", "28", "33", "34", "35", "36", "37", "38", "44", "45", "46", "47", "48", "55", "56", "57", "58", "66", "67", "68", "77", "78", "88"])
