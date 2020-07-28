import os

from p2ptrust.testing.experiments.evaluator import get_accuracy_matrix_from_results
from p2ptrust.testing.experiments.output_processor import create_enormous_table

exp_location = "/home/dita/p2ptrust-experiments-link/experiment_outputs/"
exp_prefix = "exp_"
experiments = ["1", "2a", "2b", "2c", "3a", "3b", "3c", "4a"]

tables_output_location = "/home/dita/p2ptrust-experiments-link/experiment_outputs/tables/"
tables_output_name = tables_output_location + "output_combined.tex"

exp_base = exp_location + exp_prefix
for exp_suffix in experiments:
    exp_folder = exp_base + exp_suffix

    try:
        exp_folder_walk = list(os.walk(exp_folder))[0]
    except IndexError:
        continue

    subfolders = exp_folder_walk[1]

    for subfolder_name in subfolders:
        subfolder = exp_folder + "/" + subfolder_name
        accuracy_matrix = get_accuracy_matrix_from_results(subfolder)
        table_lines = create_enormous_table(accuracy_matrix, skip_individual_ips=True)
        k = 3

