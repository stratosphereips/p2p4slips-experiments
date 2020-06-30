import os
import time

base_dirname = "experiments-" + str(time.time())
os.mkdir(base_dirname)

for experiment_id in range(0, 1):
    print("Starting experiment: " + str(experiment_id))
    data_dir = base_dirname + "/" + str(experiment_id) + "/"
    os.mkdir(data_dir)
    os.system('python3 main.py ' + str(experiment_id) + " " + data_dir + '&> ' + data_dir + 'std_out.txt')
