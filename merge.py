'''
John Carter
Created: 2021/05/13 09:04:54
Last modified: 2021/05/29 15:23:20
Merge system call and network traffic dataframes
'''

import pandas as pd
import argparse

def merge(syscall_data_path, network_data_path, output):
    syscall_data = pd.read_csv(syscall_data_path)
    network_data = pd.read_csv(network_data_path)
    
    df = pd.merge(syscall_data, network_data, how='inner', left_index=True, right_index=True) 

    print("Merged dataframe: ")
    print(df)
    
    df.to_csv(output, index=False)
    print("File saved to %s" % output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Merge system call and network traffic dataframes")
    parser.add_argument(
        "syscall_data", type=str, default=None, help="File path to find syscall data"
    )
    parser.add_argument(
        "network_data", type=str, default=None, help="File path to find network data"
    )
    parser.add_argument(
        "output", type=str, default=None, help="CSV output file"
    )
    
    args = parser.parse_args()

    merge(args.syscall_data, args.network_data, args.output)