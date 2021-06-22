'''
John Carter
Call SVM code with a grouping, data type, and malware type
Created: 2021/05/17 09:25:47
Last modified: 2021/06/12 18:12:43
'''

import argparse
import glob
import svm

INFO = '[\u001b[32mINFO\u001b[0m] '

def call_svm(benign_data, malware_data, split, window_size, data_type, malware):
    malware_type = malware_data.split("/")[2].split(".")[0]
    graph_name = window_size + "/" + malware_type + ".png"

    print("--------------------------------------------------")
    print(INFO + f"Running SVM on {malware_type} data")
    print("--------------------------------------------------")
    svm.main(benign_data, malware_data, split, graph_name, data_type, malware, n_components)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automate running the SVM")
    parser.add_argument(
        "data_type", type=str, default="all", choices=["syscalls", "packets", "merged", "all"],
        help="Type of the data (syscalls, packets, merged, or all)"
    )
    parser.add_argument(
        "malware", type=str, default=None, help="Type of malware (keylogger, cryptominer, etc.)"
    )
    parser.add_argument(
        "window_size", type=str, default=None, 
        help="Window size of data to use (5s, 30s, etc.) in processed data directory"
    )
    parser.add_argument(
        "--n_components", type=int, default=None, 
        help="Number of components for PCA"
    )
    
    args = parser.parse_args()
    data_type = args.data_type
    malware = args.malware
    window_size = args.window_size
    n_components = args.n_components

    if data_type == "all":
        types = ['syscalls', 'packets', 'merged']
        for type in types:
            benign_data = f"processed_data/{window_size}/{type}_benign.csv"
            malware_files = glob.glob(f"processed_data/{window_size}/{type}_{malware}*")

            for f in malware_files:
                name_list = f.split(".")[0].split("/")[2].split("_")
                if malware == "keylogger":
                    malware_data = f"processed_data/{window_size}/{type}_{malware}_{name_list[2]}_{name_list[3]}.csv"
                else:
                    malware_data = f"processed_data/{window_size}/{type}_{malware}_{name_list[2]}.csv"

            call_svm(benign_data, malware_data, 0.33, window_size, type, malware)

    else:
        benign_data = ''
        if data_type == "syscalls":
            benign_data = "processed_data/{}/syscalls_benign.csv".format(window_size)
        elif data_type == "packets":
            benign_data = "processed_data/{}/packets_benign.csv".format(window_size)
        elif data_type == "merged":
            benign_data = "processed_data/{}/merged_benign.csv".format(window_size)

        malware_data = ''
        if data_type == "syscalls":
            malware_data = "processed_data/{}/syscalls_{}.csv".format(window_size, malware)
        elif data_type == "packets":
            malware_data = "processed_data/{}/packets_{}.csv".format(window_size, malware)
        elif data_type == "merged":
            malware_data = "processed_data/{}/merged_{}.csv".format(window_size, malware)

        call_svm(benign_data, malware_data, 0.33, window_size, data_type, malware, n_components)