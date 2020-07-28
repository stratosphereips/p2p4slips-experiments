import os

from p2ptrust.testing.experiments.evaluator import get_accuracy_matrix_from_results
from p2ptrust.testing.experiments.output_processor import create_enormous_table

def generate_tables():
    exp_location = "/home/dita/p2ptrust-experiments-link/experiment_outputs/"
    exp_prefix = "exp_"
    experiments = ["1", "2a", "2b", "2c", "3a", "3b", "3c", "4a"]

    tables_output_location = "/home/dita/p2ptrust-experiments-link/experiment_outputs/tables/"
    tables_output_name = tables_output_location + "output_combined.tex"

    file = open(tables_output_name, "w")

    exp_base = exp_location + exp_prefix
    for exp_suffix in experiments:
        exp_folder = exp_base + exp_suffix

        try:
            exp_folder_walk = list(os.walk(exp_folder))[0]
        except IndexError:
            continue

        subfolders = exp_folder_walk[1]
        for subfolder_name in subfolders:
            print("Generating tables for experiment %s, run %s" % (exp_suffix, subfolder_name))
            subfolder = exp_folder + "/" + subfolder_name
            accuracy_matrix = get_accuracy_matrix_from_results(subfolder)

            table_lines_short = create_enormous_table(accuracy_matrix, skip_individual_ips=True, verbose=False)
            file.write("% " + exp_suffix + ", experiment id " + subfolder_name + ", short\n")
            file.writelines(["%s\n" % line for line in table_lines_short])
            file.write("\n")
            file.write("\n")

            short_file = open(tables_output_location + "exp" + exp_suffix + subfolder_name + "_short.tex", "w")
            short_file.writelines(["%s\n" % line for line in table_lines_short])
            short_file.close()

            table_lines_long = create_enormous_table(accuracy_matrix, skip_individual_ips=False, verbose=False)
            file.write("% " + exp_suffix + ", experiment id " + subfolder_name + ", long\n")
            file.writelines(["%s\n" % line for line in table_lines_long])
            file.write("\n")
            file.write("\n")

            long_file = open(tables_output_location + "exp" + exp_suffix + subfolder_name + "_long.tex", "w")
            long_file.writelines(["%s\n" % line for line in table_lines_long])
            short_file.close()
    file.close()


def generate_table_imports(exp_base="2c", iter1=None, iter2=None, long=False):
    if iter1 is None:
        iter1 = ["1", "2", "3", "4", "5", "6", "7", "8", "9"]
    if iter2 is None:
        iter2 = [""]

    output_lines = []
    for i in iter1:
        for j in iter2:
            exp_name = exp_base + i + j

            if long:
                input_file = "Tables/exp" + exp_base + "/exp" + exp_name + "_long"
                caption = exp_name
                label = "tab:" + exp_name + "-long"
            else:
                input_file = "Tables/exp" + exp_base + "/exp" + exp_name + "_short"
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


generate_tables()
generate_table_imports(long=True)
