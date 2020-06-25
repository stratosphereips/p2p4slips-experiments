import os
import time

base_dirname = "experiments-" + time.time()
os.mkdir(base_dirname)

for experiment_id in range(0, 3):
    data_dir = base_dirname + "/" + str(experiment_id) + "/"
    os.mkdir(data_dir)
    target = "8.8.8.87"
    os.system('ping ' + experiment_id + '&> tmp/Output.txt')
