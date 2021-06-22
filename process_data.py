'''
John Carter
Created: 2021/05/29 14:13:31
Last modified: 2021/06/13 17:28:53
Process all raw data for a specific time window
'''

import argparse
import glob
import os
from pathlib import Path

# import other modules in this directory
import process_syscalls 
import process_packets 
import merge

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process data for a specific time window")
    parser.add_argument(
        "data_path", type=str, default=None, help="Directory to find raw data to process"
    )
    parser.add_argument(
        "window_size", type=str, default=None, help="Window size to process at a time"
    )
    parser.add_argument(
        "--merge_data", type=bool, default=True, help="Create merged datasets of syscalls and packets"
    )
    
    args = parser.parse_args()
    data_path = args.data_path
    window_size = args.window_size
    merge_data = args.merge_data

    # check validity of raw data directory
    if not Path(data_path).is_dir():
        print("\u001b[31m\033[1mERROR: Invalid directory path\u001b[0m")

    # create data dir for this time window if it doesn't exist
    processed_data_dir = "processed_data/{}".format(window_size)
    if not os.path.exists(processed_data_dir):
        os.makedirs(processed_data_dir)
        print("\u001b[32m\033[1mINFO: Created directory {}\u001b[0m".format(processed_data_dir))

    # get raw data files
    if data_path[-1] != "/":
        data_path += "/"
    raw_data_files = glob.glob(data_path + "/*")

    # loop through raw data to process
    merged_names = []
    counter = 1
    num_files = len(raw_data_files) + 1

    for data_file in raw_data_files:
        filename, extension = os.path.splitext(data_file)
        name_list = filename.split("/")[1].split("_")
        merged_name = "_".join(name_list[1:])
        
        try:
            data_type = name_list[1]
            if data_type != "benign":
                interval = name_list[2]
            if data_type == "keylogger":
                rate = name_list[3]
        except:
            print("\u001b[31m\033[1mERROR: Invalid filename '{}' in {}. Skipping...\u001b[0m".format(filename, data_path))
            continue
            
        print(f"\u001b[32m\033[1mINFO: Processing {data_file} ({counter}/{num_files} done).\u001b[0m")
        counter += 1
        if merged_name not in merged_names:
            merged_names.append(merged_name)

        if extension == ".csv":
            if data_type == "keylogger":
                output_filename = processed_data_dir + "/packets_{}_{}_{}.csv".format(data_type, interval, rate)
            elif data_type == "benign":
                output_filename = processed_data_dir + f"/packets_{data_type}.csv"
            else:
                output_filename = processed_data_dir + "/packets_{}_{}.csv".format(data_type, interval)
            if os.path.exists(output_filename):
                print("\u001b[32m\033[1mINFO: File {} exists. Skipping...\u001b[0m".format(output_filename))
            else: 
                process_packets.process_packets(data_file, output_filename, window_size)

        elif extension == ".log":
            if data_type == "keylogger":
                output_filename = processed_data_dir + "/syscalls_{}_{}_{}.csv".format(data_type, interval, rate)
            elif data_type == "benign":
                output_filename = processed_data_dir + f"/syscalls_{data_type}.csv"
            else:
                output_filename = processed_data_dir + "/syscalls_{}_{}.csv".format(data_type, interval)
            if os.path.exists(output_filename):
                print("\u001b[32m\033[1mINFO: File {} exists. Skipping...\u001b[0m".format(output_filename))
            else:
                process_syscalls.process_syscalls(data_file, output_filename, window_size)
            
        else:
            print("\u001b[31m\033[1mERROR: Invalid file type. Must be .csv or .log\u001b[0m")

    # merge data if selected
    if merge_data:
        for name in merged_names:

            # Get output filename based on details of file
            name_list = name.split("_")
            data_type = name_list[0]
            if data_type == "keylogger":
                output_filename = processed_data_dir + f"/merged_{data_type}_{name_list[1]}_{name_list[2]}.csv"
            elif data_type == "benign":
                output_filename = processed_data_dir + f"/merged_{data_type}.csv"
            else:
                output_filename = processed_data_dir + f"/merged_{data_type}_{name_list[1]}.csv"
            
            
            # Do the merge process
            if os.path.exists(output_filename):
                print(f"\u001b[32m\033[1mINFO: Merged file {output_filename} exists. Skipping...\u001b[0m")   
            else:   
                print(f"\u001b[32m\033[1mINFO: Merging {data_type} data\u001b[0m")
                if data_type == "keylogger":
                    syscall_file = processed_data_dir + f"/syscalls_{data_type}_{name_list[1]}_{name_list[2]}.csv"
                    packet_file = processed_data_dir + f"/packets_{data_type}_{name_list[1]}_{name_list[2]}.csv"
                elif data_type == "benign":
                    syscall_file = processed_data_dir + f"/syscalls_{data_type}.csv"
                    packet_file = processed_data_dir + f"/packets_{data_type}.csv"
                else:
                    syscall_file = processed_data_dir + f"/syscalls_{data_type}_{name_list[1]}.csv"
                    packet_file = processed_data_dir + f"/packets_{data_type}_{name_list[1]}.csv"
                
                merge.merge(syscall_file, packet_file, output_filename)